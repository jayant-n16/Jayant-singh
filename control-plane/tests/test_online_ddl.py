"""FR-02 online DDL. Planner rules run everywhere; the PostgreSQL and MySQL tests run real servers
(OPLIA_TEST_DATABASE_URL, scripts/test-mysql.sh) and check the declared lock modes against pg_locks,
concurrent writers' latency while a long transaction holds the table, and the end state."""

from __future__ import annotations

import json
import os
import threading
import time

import pytest
from fastapi.testclient import TestClient

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.databases.registry import DatabaseRegistry, DatabaseSpec
from oplia_ctl.migration.online_ddl import (
    ColumnInfo,
    OnlineSchemaChange,
    Runner,
    SchemaChange,
    SchemaContract,
    TableInfo,
    build_plan,
    normalise_type,
    parse_expression,
    table_info,
)
from oplia_ctl.replication.config import ReplicationSettings, build_job_machines
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer

PG_URL = os.environ.get("OPLIA_TEST_DATABASE_URL", "").replace("postgresql+psycopg://", "postgresql://")
MYSQL_PORT = os.environ.get("OPLIA_TEST_MYSQL_PORT", "")

INFO = TableInfo(columns={"id": ColumnInfo("id", "bigint", False, None, []),
                          "amount": ColumnInfo("amount", "integer", True, None, []),
                          "sku": ColumnInfo("sku", "text", True, None, ["index ix_sku"]),
                          "Note": ColumnInfo("Note", "text", True, None, [])},
                 pk=["id"], indexes=["orders_pkey", "ix_sku"])


def _change(*ops, **kw):
    return SchemaChange.model_validate({"database": "app", "table": "orders", "operations": list(ops), **kw})


# ----------------------------------------------------------------------------- planner (no database)
def test_types_and_expressions_are_parsed_not_pasted():
    assert normalise_type("numeric(12,2)", "postgres") == "DECIMAL(12, 2)"
    assert normalise_type("bigint unsigned", "mysql") == "BIGINT UNSIGNED"
    for bad in ("text; DROP TABLE x", "int -- x", "nosuchtype", ""):
        with pytest.raises(ValueError):
            normalise_type(bad, "postgres")
    with pytest.raises(ValueError, match="subqueries"):
        parse_expression("amount > (SELECT 1)", "postgres", {"amount"})
    with pytest.raises(ValueError, match="only use these columns"):
        parse_expression("other > 0", "postgres", {"amount"})
    with pytest.raises(ValueError, match="statement"):
        parse_expression("DROP TABLE orders", "postgres", {"amount"})


def test_pg_plan_lock_tags_and_refusals():
    p = build_plan(_change({"op": "add_index", "name": "ix_amount", "columns": ["amount"]},
                           {"op": "change_type", "column": "amount", "type": "bigint"},
                           {"op": "rename_column", "column": "Note", "new_name": "remark"}), "postgres", INFO, {})
    assert p.expand[0].sql == 'CREATE INDEX CONCURRENTLY IF NOT EXISTS "ix_amount" ON "public"."orders" ("amount")'
    assert p.expand[0].autocommit and p.expand[0].lock == "SHARE UPDATE EXCLUSIVE"
    assert 'NEW."amount__oplia_new" := CAST(NEW."amount" AS BIGINT)' in p.expand[2].sql
    assert [b.column for b in p.backfill] == ["amount__oplia_new", "remark"]
    assert any('RENAME COLUMN "amount__oplia_new" TO "amount"' in s.sql for s in p.contract)
    assert p.contract[-1].sql == 'ALTER TABLE "public"."orders" DROP COLUMN IF EXISTS "Note"'
    with pytest.raises(ValueError, match="forbid_access_exclusive"):
        build_plan(_change({"op": "add_column", "column": "x", "type": "int"}, forbid_access_exclusive=True),
                   "postgres", INFO, {})
    ok = build_plan(_change({"op": "add_index", "name": "ix2", "columns": ["amount"]}, forbid_access_exclusive=True),
                    "postgres", INFO, {})
    assert ok.expand[0].lock == "SHARE UPDATE EXCLUSIVE"
    for op, msg in (({"op": "change_type", "column": "id", "type": "text"}, "primary key"),
                    ({"op": "change_type", "column": "sku", "type": "varchar(5)"}, "used by index ix_sku"),
                    ({"op": "add_column", "column": "y", "type": "int", "nullable": False}, "constant default"),
                    ({"op": "add_index", "name": "ix3", "columns": ["nope"]}, "does not exist"),
                    ({"op": "drop_index", "name": "nope"}, "does not exist")):
        with pytest.raises(ValueError, match=msg):
            build_plan(_change(op), "postgres", INFO, {})
    with pytest.raises(ValueError):
        _change({"op": "add_index", "name": 'x"; DROP TABLE y; --', "columns": ["amount"]})


def test_mysql_plan_never_allows_a_blocking_copy():
    p = build_plan(_change({"op": "add_column", "column": "c", "type": "int"},
                           {"op": "add_index", "name": "ix_c", "columns": ["amount"]},
                           {"op": "change_type", "column": "amount", "type": "bigint"}), "mysql", INFO, {})
    alters = [s.sql for s in p.expand + p.contract if s.sql.startswith("ALTER TABLE")]
    assert alters and all("ALGORITHM=INSTANT" in a or "ALGORITHM=INPLACE, LOCK=NONE" in a for a in alters)
    assert not any("COPY" in a for a in alters)


class _FakeMy:
    def __init__(self, answers):
        self.answers = list(answers)

    def cursor(self):
        outer = self

        class C:
            description = True

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, args=None):
                self.rows = outer.answers.pop(0)

            def fetchall(self):
                return self.rows
        return C()


def test_mysql_trigger_precheck():
    from oplia_ctl.migration.online_ddl import mysql_trigger_precheck

    mysql_trigger_precheck(_FakeMy([[(1, 1)]]))                       # trust on: fine
    mysql_trigger_precheck(_FakeMy([[(0, 0)]]))                       # no binlog: fine
    mysql_trigger_precheck(_FakeMy([[(1, 0)], [("ops@%",)], [(1,)]]))  # SUPER: fine
    with pytest.raises(ValueError, match="log_bin_trust_function_creators=1"):
        mysql_trigger_precheck(_FakeMy([[(1, 0)], [("ops@%",)], [(0,)]]))


def test_kill_switch_halts_the_worker(session_factory):
    reg = DatabaseRegistry([DatabaseSpec(name="app", engine="postgres", cloud="aws", role="primary",
                                         dsn_secret="d")], StaticSecretProvider({"d": "postgresql://x/y"}),
                           session_factory)
    m = OnlineSchemaChange(reg, session_factory)
    payload = m.parse({"change": json.dumps({"database": "app", "table": "orders",
                                             "operations": [{"op": "drop_column", "column": "x"}]})})
    jid = m(payload)["job_id"]
    m.halted = lambda: True
    out = m.run_pending()
    assert out[0]["halted"] and m.get(jid)["status"] == "QUEUED" and m.get(jid)["step"] == "PLAN"


def test_wiring_and_api_propose(monkeypatch, gate, session_factory):
    monkeypatch.setenv("OPLIA_MIGRATION_ONLINE_DDL", "true")
    monkeypatch.setenv("OPLIA_DATABASES", json.dumps([{"name": "app", "engine": "postgres", "cloud": "aws",
                                                        "role": "primary", "dsn_secret": "app_dsn"}]))
    machines = build_job_machines(ReplicationSettings(), session_factory,
                                  secrets=StaticSecretProvider({"app_dsn": "postgresql://x/y"}),
                                  halted=lambda: False)
    assert {"schema_change", "schema_contract"} <= set(machines)
    client = TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={m.action: m for m in machines.values()}, webhook_secret_name="webhook_hmac_secret",
        webhook_max_skew_seconds=300, allowed_blueprints=["control-tower-standard"],
        approver_role="oplia-approver", operator_role="oplia-operator", dr_jobs=machines))
    h = bearer("bob", "oplia-operator")
    change = {"table": "orders", "operations": [{"op": "add_index", "name": "ix_c", "columns": ["c"]}]}
    r = client.post("/dr/jobs/schema_change", headers=h,
                    json={"params": {"database": "app", "change": json.dumps(change)}, "reason": "speed up lookups"})
    assert r.status_code == 201, r.text
    assert "lock_timeout 2000 ms" in r.json()["reason"] and r.json()["action_type"] == "migration.schema_change"
    bad = {"table": "orders", "operations": [{"op": "add_check", "name": "c1", "expression": "1"}],
           "lock_timeout_ms": 1}
    r = client.post("/dr/jobs/schema_change", headers=h,
                    json={"params": {"database": "app", "change": json.dumps(bad)}, "reason": "x"})
    assert r.status_code == 422
    monkeypatch.setenv("OPLIA_DATABASES", "[]")
    with pytest.raises(ValueError, match="postgres or mysql"):
        build_job_machines(ReplicationSettings(), session_factory, secrets=StaticSecretProvider({}))


# ----------------------------------------------------------------------------- PostgreSQL (real server)
@pytest.fixture
def pg_app():
    if not PG_URL:
        pytest.skip("needs PostgreSQL (OPLIA_TEST_DATABASE_URL)")
    import psycopg

    base = PG_URL.rsplit("/", 1)[0]
    with psycopg.connect(PG_URL, autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS odl_app WITH (FORCE)")
        c.execute("CREATE DATABASE odl_app ENCODING 'UTF8' TEMPLATE template0")
    dsn = f"{base}/odl_app"
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("CREATE TABLE customers (id int PRIMARY KEY, name text)")
        c.execute("INSERT INTO customers SELECT g, 'c' || g FROM generate_series(1, 50) g")
        c.execute('CREATE TABLE orders (id bigint PRIMARY KEY, customer_id int, amount int, "Note" text, '
                  "status text)")
        c.execute("INSERT INTO orders SELECT g, g % 50 + 1, g, 'n' || g, CASE WHEN g % 10 = 0 THEN NULL "
                  "ELSE 'ok' END FROM generate_series(1, 5000) g")
    yield dsn


def _pg_machines(session_factory, dsn, events):
    reg = DatabaseRegistry([DatabaseSpec(name="app", engine="postgres", cloud="aws", role="primary",
                                         dsn_secret="d")], StaticSecretProvider({"d": dsn}), session_factory)
    ex = OnlineSchemaChange(reg, session_factory, audit=lambda e, d: events.append((e, d)), max_batches_per_step=3)
    return reg, ex, SchemaContract(ex, reg, session_factory, audit=lambda e, d: events.append((e, d)))


def _drive(m, jid, limit=200):
    for _ in range(limit):
        m.run_pending()
        j = m.get(jid)
        if j["status"] in ("SUCCEEDED", "FAILED"):
            return j
    raise AssertionError(f"job did not finish: {m.get(jid)}")


PG_MODES = {"ACCESS EXCLUSIVE (catalog only)": "AccessExclusiveLock", "SHARE ROW EXCLUSIVE": "ShareRowExclusiveLock",
            "SHARE UPDATE EXCLUSIVE": "ShareUpdateExclusiveLock", "none": None}
ORDER = ["AccessShareLock", "RowShareLock", "RowExclusiveLock", "ShareUpdateExclusiveLock", "ShareLock",
         "ShareRowExclusiveLock", "ExclusiveLock", "AccessExclusiveLock"]


def test_pg_declared_lock_modes_match_pg_locks(pg_app):
    """Each transactional statement is first run in a transaction that is rolled back while we read the
    strongest lock it holds on the table from pg_locks; then it is run for real (so the next one has its
    prerequisites)."""
    import psycopg

    change = _change({"op": "add_column", "column": "discount", "type": "int", "default": 0},
                     {"op": "add_foreign_key", "name": "fk_cust", "columns": ["customer_id"],
                      "ref_table": "customers", "ref_columns": ["id"]},
                     {"op": "add_check", "name": "ck_amount", "expression": "amount >= 0"},
                     {"op": "set_not_null", "column": "Note"},
                     {"op": "change_type", "column": "amount", "type": "bigint"},
                     {"op": "rename_column", "column": "Note", "new_name": "remark"})
    with psycopg.connect(pg_app, autocommit=True) as c:
        info = table_info(c, "postgres", "orders")
        plan = build_plan(change, "postgres", info, {"customers": table_info(c, "postgres", "customers")})
        seen = []
        for s in plan.expand + plan.validate + plan.contract:
            if not s.autocommit:
                with c.transaction() as tx:
                    c.execute(s.sql)
                    modes = [r[0] for r in c.execute(
                        "SELECT mode FROM pg_locks WHERE pid = pg_backend_pid() AND granted "
                        "AND relation = 'public.orders'::regclass").fetchall()]
                    strongest = max(modes, key=ORDER.index) if modes else None
                    seen.append((s.sql[:60], s.lock, strongest))
                    raise psycopg.Rollback(tx)
            Runner(c, "postgres", change).run(s)
        print("\n".join(f"{d:33} {m!s:26} {q}" for q, d, m in seen))
        for sql, declared, strongest in seen:
            want = PG_MODES[declared]
            got = ORDER.index(strongest) if strongest else -1
            # the declared mode is an upper bound (DROP ... IF EXISTS on a missing object takes no lock)
            assert got <= (ORDER.index(want) if want else 0), (sql, declared, strongest)
            if want and "IF EXISTS" not in sql:
                assert strongest == want, (sql, declared, strongest)
        assert {d for _, d, _ in seen} >= {"ACCESS EXCLUSIVE (catalog only)", "SHARE ROW EXCLUSIVE",
                                           "SHARE UPDATE EXCLUSIVE"}


def test_pg_expand_backfill_validate_contract_under_load(gate, session_factory, pg_app):
    import psycopg

    events: list = []
    _, ex, contract = _pg_machines(session_factory, pg_app, events)
    change = {"table": "orders", "lock_timeout_ms": 100, "batch_size": 700, "batch_pause_ms": 0,
              "operations": [
                  {"op": "add_index", "name": "ix_orders_customer", "columns": ["customer_id"]},
                  {"op": "add_foreign_key", "name": "fk_orders_customer", "columns": ["customer_id"],
                   "ref_table": "customers", "ref_columns": ["id"]},
                  {"op": "add_check", "name": "ck_amount_positive", "expression": "amount >= 0"},
                  {"op": "set_not_null", "column": "Note"},
                  {"op": "change_type", "column": "amount", "type": "bigint"},
                  {"op": "rename_column", "column": "Note", "new_name": "remark"}]}
    p = gate.propose(action_type=ex.action, target="app:orders", payload={**ex.parse({"database": "app",
                     "change": json.dumps(change)}), "requested_by": "bob"}, reason="r", requested_by="bob")
    gate.approve(p.id, "alice")
    jid = gate.execute(p.id, ex, "ops").result["job_id"]

    # a long transaction holds ACCESS SHARE for 1.5 s; a writer keeps updating rows meanwhile
    blocker = psycopg.connect(pg_app)
    blocker.execute("SELECT count(*) FROM orders").fetchone()
    threading.Timer(1.5, blocker.rollback).start()
    stop, lat, errors = threading.Event(), [], []

    def writer():
        with psycopg.connect(pg_app, autocommit=True) as w:
            i = 0
            while not stop.is_set():
                t0 = time.monotonic()
                try:
                    w.execute('UPDATE orders SET "Note" = %s WHERE id = %s', (f"w{i}", 1 + i % 5000))
                    w.execute('INSERT INTO orders (id, customer_id, amount, "Note") VALUES (%s, 7, %s, %s)',
                              (100000 + i, i, f"new{i}"))
                except Exception as e:  # the writer must never fail
                    errors.append(repr(e))
                lat.append(time.monotonic() - t0)
                i += 1
                time.sleep(0.005)

    t = threading.Thread(target=writer)
    t.start()
    try:
        job = _drive(ex, jid)
    finally:
        stop.set()
        t.join()
        blocker.close()
    assert job["status"] == "SUCCEEDED", job
    st = job["state"]
    assert errors == []
    assert max(lat) < 1.0, f"a writer waited {max(lat):.2f}s"
    assert any(not a["ok"] for a in st["attempts"]), "expected lock_timeout retries while the blocker held the table"
    assert st["rows_backfilled"] >= 5000 and st["awaiting_contract"] is True
    assert all(c["offending_rows"] == 0 for c in st["checks"])

    with psycopg.connect(pg_app, autocommit=True) as c:
        # trigger keeps both columns in sync for writes made after EXPAND, both directions
        c.execute('UPDATE orders SET "Note" = %s WHERE id = 3', ("via-old",))
        assert c.execute("SELECT remark, amount__oplia_new FROM orders WHERE id = 3").fetchone() == ("via-old", 3)
        c.execute("UPDATE orders SET remark = %s WHERE id = 4", ("via-new",))
        assert c.execute('SELECT "Note" FROM orders WHERE id = 4').fetchone() == ("via-new",)
        assert c.execute("SELECT convalidated FROM pg_constraint WHERE conname = 'fk_orders_customer'").fetchone() == (
            True,)
        assert c.execute("SELECT attnotnull FROM pg_attribute WHERE attrelid = 'orders'::regclass "
                         "AND attname = 'Note'").fetchone() == (True,)
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute('INSERT INTO orders (id, customer_id, amount, "Note") VALUES (-1, 1, -5, %s)', ("x",))

    p2 = gate.propose(action_type=contract.action, target="app:orders",
                      payload={**contract.parse({"expand_job_id": jid}), "requested_by": "bob"}, reason="r",
                      requested_by="bob")
    gate.approve(p2.id, "alice")
    cj = _drive(contract, gate.execute(p2.id, contract, "ops").result["job_id"])
    assert cj["status"] == "SUCCEEDED", cj
    with psycopg.connect(pg_app, autocommit=True) as c:
        cols = dict(c.execute("SELECT attname, format_type(atttypid, atttypmod) FROM pg_attribute WHERE "
                              "attrelid = 'orders'::regclass AND attnum > 0 AND NOT attisdropped").fetchall())
        assert cols["amount"] == "bigint" and "remark" in cols and "Note" not in cols
        assert not any(k.endswith("__oplia_new") or k.endswith("__oplia_old") for k in cols)
        assert c.execute("SELECT count(*) FROM pg_trigger WHERE tgrelid = 'orders'::regclass "
                         "AND NOT tgisinternal").fetchone() == (0,)
        assert c.execute("SELECT amount, remark FROM orders WHERE id = 4").fetchone() == (4, "via-new")
    assert [e for e, _ in events] == ["migration.schema_change.succeeded", "migration.schema_contract.succeeded"]


def test_pg_validation_failure_stops_before_constraint(gate, session_factory, pg_app):
    events: list = []
    _, ex, contract = _pg_machines(session_factory, pg_app, events)
    jid = ex(ex.parse({"database": "app", "change": json.dumps(
        {"table": "orders", "operations": [{"op": "set_not_null", "column": "status"}]})}))["job_id"]
    job = _drive(ex, jid)
    assert job["status"] == "FAILED" and "violat" in job["error"].lower(), job["error"]
    with pytest.raises(ValueError, match="SUCCEEDED"):
        contract.parse({"expand_job_id": jid})


# ----------------------------------------------------------------------------- MySQL (real server)
@pytest.fixture
def mysql_tables():
    """Tables live in app_src, which other tests compare with app_dr: always drop them afterwards."""
    import pymysql

    yield
    pw = os.environ["OPLIA_TEST_MYSQL_PW"]
    with pymysql.connect(host="127.0.0.1", port=int(MYSQL_PORT), user="oplia_cc", password=pw, database="app_src",
                         autocommit=True) as c, c.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS m_orders, m_customers")


@pytest.mark.skipif(not MYSQL_PORT, reason="needs MySQL (scripts/test-mysql.sh)")
def test_mysql_online_change_with_concurrent_writes(session_factory, mysql_tables):
    import pymysql

    pw = os.environ["OPLIA_TEST_MYSQL_PW"]
    dsn = f"mysql://oplia_cc:{pw}@127.0.0.1:{MYSQL_PORT}/app_src"

    def conn():
        return pymysql.connect(host="127.0.0.1", port=int(MYSQL_PORT), user="oplia_cc", password=pw,
                               database="app_src", autocommit=True)

    with conn() as c, c.cursor() as cur:
        for t in ("m_orders", "m_customers"):
            cur.execute(f"DROP TABLE IF EXISTS {t}")
        cur.execute("CREATE TABLE m_customers (id INT PRIMARY KEY)")
        cur.executemany("INSERT INTO m_customers VALUES (%s)", [(i,) for i in range(1, 51)])
        cur.execute("CREATE TABLE m_orders (id INT PRIMARY KEY, customer_id INT, amount INT, Note VARCHAR(50))")
        cur.executemany("INSERT INTO m_orders VALUES (%s, %s, %s, %s)",
                        [(i, i % 50 + 1, i, f"n{i}") for i in range(1, 3001)])
    events: list = []
    reg = DatabaseRegistry([DatabaseSpec(name="app", engine="mysql", cloud="azure", role="primary",
                                         dsn_secret="d")], StaticSecretProvider({"d": dsn}), session_factory)
    ex = OnlineSchemaChange(reg, session_factory, audit=lambda e, d: events.append(e), max_batches_per_step=2)
    contract = SchemaContract(ex, reg, session_factory)
    change = {"table": "m_orders", "batch_size": 500, "batch_pause_ms": 0, "operations": [
        {"op": "add_column", "column": "discount", "type": "int", "default": 0, "nullable": False},
        {"op": "add_index", "name": "ix_m_cust", "columns": ["customer_id"]},
        {"op": "add_foreign_key", "name": "fk_m_cust", "columns": ["customer_id"], "ref_table": "m_customers",
         "ref_columns": ["id"]},
        {"op": "change_type", "column": "amount", "type": "bigint"},
        {"op": "rename_column", "column": "Note", "new_name": "remark"}]}
    jid = ex(ex.parse({"database": "app", "change": json.dumps(change)}))["job_id"]
    stop, errors, lat = threading.Event(), [], []

    def writer():
        with conn() as w, w.cursor() as cur:
            i = 0
            while not stop.is_set():
                t0 = time.monotonic()
                try:
                    cur.execute("UPDATE m_orders SET Note = %s WHERE id = %s", (f"w{i}", 1 + i % 3000))
                except Exception as e:
                    errors.append(repr(e))
                lat.append(time.monotonic() - t0)
                i += 1
                time.sleep(0.005)

    t = threading.Thread(target=writer)
    t.start()
    try:
        job = _drive(ex, jid)
    finally:
        stop.set()
        t.join()
    assert job["status"] == "SUCCEEDED", (job["error"], job["state"].get("failed_step"))
    assert errors == [] and max(lat) < 2.0
    with conn() as c, c.cursor() as cur:
        cur.execute("UPDATE m_orders SET remark = 'via-new' WHERE id = 9")
        cur.execute("SELECT Note, amount__oplia_new FROM m_orders WHERE id = 9")
        assert cur.fetchone() == ("via-new", 9)
    cj = _drive(contract, contract(contract.parse({"expand_job_id": jid}))["job_id"])
    assert cj["status"] == "SUCCEEDED", cj
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'app_src' "
                    "AND TABLE_NAME = 'm_orders'")
        cols = dict(cur.fetchall())
        assert cols["amount"] == "bigint" and "remark" in cols and "Note" not in cols and cols["discount"] == "int"
        cur.execute("SELECT amount, remark FROM m_orders WHERE id = 9")
        assert cur.fetchone() == (9, "via-new")
    assert events == ["migration.schema_change.succeeded"]
