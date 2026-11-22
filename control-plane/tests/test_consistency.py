from __future__ import annotations

import os

import pytest

from oplia_ctl.databases.consistency import ACTION_DR_RESYNC, ConsistencyChecker, ConsistencySettings
from oplia_ctl.databases.registry import DatabaseRegistry, DatabaseSpec
from oplia_ctl.databases.resync import ResyncExecutor
from oplia_ctl.safety import ProposalStatus
from oplia_ctl.secrets import StaticSecretProvider

PG_URL = os.environ.get("OPLIA_TEST_DATABASE_URL", "").replace("postgresql+psycopg://", "postgresql://")
MYSQL_PORT = os.environ.get("OPLIA_TEST_MYSQL_PORT", "")
CFG = ConsistencySettings(recheck_delay_seconds=0, checksum_chunk_rows=100)


def _specs(engine, src_db, dst_db):
    return [DatabaseSpec(name="src", engine=engine, cloud="aws", role="primary", dsn_secret="s", database=src_db),
            DatabaseSpec(name="dr", engine=engine, cloud="azure", role="dr", dr_of="src", dsn_secret="d",
                         database=dst_db)]


# ----------------------------------------------------------------------------- PostgreSQL
@pytest.fixture
def pg_pair():
    if not PG_URL:
        pytest.skip("needs PostgreSQL (OPLIA_TEST_DATABASE_URL)")
    import psycopg

    base = PG_URL.rsplit("/", 1)[0]
    with psycopg.connect(PG_URL, autocommit=True) as c:
        for db in ("cc_src", "cc_dr"):
            c.execute(f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")
            c.execute(f"CREATE DATABASE {db} ENCODING 'UTF8' TEMPLATE template0")
    conns = {db: psycopg.connect(f"{base}/{db}", autocommit=True) for db in ("cc_src", "cc_dr")}
    for c in conns.values():
        c.execute("CREATE TABLE orders (id int PRIMARY KEY, amount numeric(12,2), note text, at timestamptz)")
        c.execute("CREATE TABLE lines (order_id int, line int, sku text, PRIMARY KEY (order_id, line))")
        c.execute("CREATE TABLE audit_nopk (x int)")
        c.execute("INSERT INTO orders SELECT g, g * 1.5, 'n' || g, '2026-01-01'::timestamptz + g * interval '1 min' "
                  "FROM generate_series(1, 250) g")
        c.execute("INSERT INTO lines SELECT g / 3, g % 3, 'sku' || g FROM generate_series(1, 330) g")
        c.execute("INSERT INTO audit_nopk VALUES (1), (2)")
    yield conns, {"s": f"{base}/cc_src", "d": f"{base}/cc_dr"}
    for c in conns.values():
        c.close()


def _checker(gate, session_factory, specs, secrets, **kw):
    reg = DatabaseRegistry(specs, StaticSecretProvider(secrets), session_factory)
    return reg, ConsistencyChecker(reg, gate, session_factory, cfg=kw.pop("cfg", CFG), **kw)


def test_pg_consistent_then_drift_then_resync(gate, session_factory, pg_pair):
    conns, secrets = pg_pair
    reg, checker = _checker(gate, session_factory, _specs("postgres", "cc_src", "cc_dr"), secrets)
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "CONSISTENT", r
    t = r["report"]["tables"]
    assert t["public.orders"] == {"source_rows": 250, "target_rows": 250, "match": True, "checksum": "match"}
    assert t["public.lines"]["checksum"] == "match"  # composite key, 4 chunks of 100
    assert t["public.audit_nopk"]["checksum"].startswith("skipped: no primary key")
    assert r["proposal_id"] is None

    conns["cc_dr"].execute("UPDATE orders SET amount = amount + 0.01 WHERE id = 200")   # same count, other data
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "DRIFT" and r["report"]["tables"]["public.orders"]["checksum"] == "differ"
    assert r["report"]["tables"]["public.orders"]["rechecked"] is True
    p = gate.get(r["proposal_id"])
    assert p.action_type == ACTION_DR_RESYNC and p.payload["tables"] == ["public.orders"]
    events = [e["event"] for e in gate.list_audit(limit=5)]
    assert "dr_consistency_check" in events

    gate.approve(p.id, "bob")
    done = gate.execute(p.id, ResyncExecutor(reg, CFG), "ops")
    assert done.status is ProposalStatus.EXECUTED, done.result
    assert done.result["tables"] == [{"table": "public.orders", "rows_copied": 250, "verified": True,
                                      "source_rows": 250, "target_rows": 250}]
    assert checker.run("dr", triggered_by="alice")["status"] == "CONSISTENT"


def test_pg_schema_drift_is_reported_and_never_copied(gate, session_factory, pg_pair):
    conns, secrets = pg_pair
    conns["cc_dr"].execute("ALTER TABLE orders ADD COLUMN extra int")
    conns["cc_dr"].execute("DROP TABLE lines")
    reg, checker = _checker(gate, session_factory, _specs("postgres", "cc_src", "cc_dr"), secrets)
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "DRIFT"
    issues = {(s["table"], s["issue"]) for s in r["report"]["schema"]}
    assert issues == {("public.orders", "columns differ"), ("public.lines", "missing on DR target")}
    gate.approve(r["proposal_id"], "bob")
    done = gate.execute(r["proposal_id"], ResyncExecutor(reg, CFG), "ops")
    assert done.status is ProposalStatus.FAILED and "migration first" in done.result["error"]


def test_pg_schema_difference_does_not_hide_changed_data(gate, session_factory, pg_pair):
    # the user's case: the expand step added a column on the source only, then a row changed on the source
    conns, secrets = pg_pair
    conns["cc_src"].execute("ALTER TABLE orders ADD COLUMN amount__oplia_new numeric(14,2)")
    conns["cc_src"].execute("UPDATE orders SET amount = 999 WHERE id = 1")
    _reg, checker = _checker(gate, session_factory, _specs("postgres", "cc_src", "cc_dr"), secrets)
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "DRIFT"
    assert [(s["table"], s["issue"]) for s in r["report"]["schema"]] == [("public.orders", "columns differ")]
    orders = r["report"]["tables"]["public.orders"]
    assert orders["checksum"] == "differ" and orders["match"] is False
    assert orders["compared_columns"] == ["id", "amount", "note", "at"]
    assert "1 table(s) with different data: public.orders" in r["summary"]
    assert gate.get(r["proposal_id"]).payload["tables"] == ["public.orders"]
    # the same extra column with identical data: schema drift only, the data matches
    conns["cc_src"].execute("UPDATE orders SET amount = 1.5 WHERE id = 1")
    r = checker.run("dr", triggered_by="alice")
    assert r["report"]["tables"]["public.orders"]["checksum"] == "match"
    assert r["status"] == "DRIFT" and "different data" not in r["summary"]


def test_repeated_checks_of_the_same_drift_reuse_one_proposal(gate, session_factory, pg_pair):
    conns, secrets = pg_pair
    conns["cc_dr"].execute("DELETE FROM orders WHERE id = 3")
    _reg, checker = _checker(gate, session_factory, _specs("postgres", "cc_src", "cc_dr"), secrets)
    first = checker.run("dr", triggered_by="alice")
    again = checker.run("dr", triggered_by="alice")
    assert first["proposal_id"] and again["proposal_id"] == first["proposal_id"]
    assert again["report"]["resync_proposal_reused"] is True
    assert len([p for p in gate.list() if p.action_type == ACTION_DR_RESYNC]) == 1
    gate.approve(first["proposal_id"], "bob")                       # still open (APPROVED): reused
    assert checker.run("dr", triggered_by="alice")["proposal_id"] == first["proposal_id"]
    conns["cc_dr"].execute("DELETE FROM orders WHERE id = 4")      # more rows of the same table: same resync
    assert checker.run("dr", triggered_by="alice")["proposal_id"] == first["proposal_id"]
    conns["cc_dr"].execute("DELETE FROM lines WHERE order_id = 7")  # another table: a different resync
    other = checker.run("dr", triggered_by="alice")
    assert other["proposal_id"] != first["proposal_id"]
    gate.reject(other["proposal_id"], "bob")                        # decided: the next check proposes again
    assert checker.run("dr", triggered_by="alice")["proposal_id"] not in (first["proposal_id"], other["proposal_id"])


def test_pg_resync_refuses_a_locked_target(gate, session_factory, pg_pair):
    conns, secrets = pg_pair
    conns["cc_dr"].execute("DELETE FROM orders WHERE id = 1")
    conns["cc_dr"].execute("ALTER DATABASE cc_dr SET default_transaction_read_only = on")
    reg, checker = _checker(gate, session_factory, _specs("postgres", "cc_src", "cc_dr"), secrets)
    r = checker.run("dr", triggered_by="alice")
    assert r["report"]["tables"]["public.orders"]["match"] is False
    gate.approve(r["proposal_id"], "bob")
    done = gate.execute(r["proposal_id"], ResyncExecutor(reg, CFG), "ops")
    assert done.status is ProposalStatus.FAILED and "read-only" in done.result["error"]
    conns["cc_dr"].execute("SET default_transaction_read_only = off")
    conns["cc_dr"].execute("ALTER DATABASE cc_dr RESET default_transaction_read_only")


def test_transient_difference_cleared_by_recheck(gate, session_factory, pg_pair):
    conns, secrets = pg_pair
    conns["cc_dr"].execute("DELETE FROM orders WHERE id = 5")

    def replication_catches_up(_seconds):
        conns["cc_dr"].execute("INSERT INTO orders SELECT * FROM (VALUES (5, 7.50::numeric, 'n5', "
                               "'2026-01-01'::timestamptz + 5 * interval '1 min')) v")

    _reg, checker = _checker(gate, session_factory, _specs("postgres", "cc_src", "cc_dr"), secrets,
                            sleep=replication_catches_up)
    r = checker.run("dr", triggered_by="scheduler")
    assert r["status"] == "CONSISTENT" and r["report"]["tables"]["public.orders"]["rechecked"] is True


def test_open_breaker_means_no_resync_proposal(gate, session_factory, pg_pair):
    conns, secrets = pg_pair
    conns["cc_dr"].execute("DELETE FROM orders WHERE id = 9")
    _reg, checker = _checker(gate, session_factory, _specs("postgres", "cc_src", "cc_dr"), secrets,
                            breaker_state=lambda: {"stream": "orders", "state": "OPEN", "incident_id": "i-1"})
    r = checker.run("dr", triggered_by="scheduler")
    assert r["status"] == "DRIFT" and r["proposal_id"] is None and "breaker is OPEN" in r["summary"]
    assert r["report"]["dr_breaker"]["incident_id"] == "i-1"


def test_failure_is_recorded_without_secrets(gate, session_factory):
    _reg, checker = _checker(gate, session_factory, _specs("postgres", "x", "y"),
                            {"s": "postgresql://u:topsecret@127.0.0.1:1/x", "d": "postgresql://u:topsecret@127.0.0.1:1/y"})
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "FAILED" and "topsecret" not in r["summary"]
    assert checker.list_runs("dr")[0]["status"] == "FAILED"
    with pytest.raises(LookupError):
        checker.run("src", triggered_by="alice")


# ----------------------------------------------------------------------------- MySQL
@pytest.mark.skipif(not MYSQL_PORT, reason="needs MySQL (scripts/test-mysql.sh)")
def test_mysql_drift_and_resync_across_differently_named_schemas(gate, session_factory):
    import pymysql

    pw = os.environ["OPLIA_TEST_MYSQL_PW"]
    conns = {db: pymysql.connect(host="127.0.0.1", port=int(MYSQL_PORT), user="oplia_cc", password=pw, database=db,
                                 autocommit=True) for db in ("app_src", "app_dr")}
    try:
        for c in conns.values():
            with c.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS products")
                cur.execute("CREATE TABLE products (id INT PRIMARY KEY, name VARCHAR(50), price DECIMAL(10,2))")
                cur.executemany("INSERT INTO products VALUES (%s, %s, %s)",
                                [(i, f"p{i}", i * 2.5) for i in range(1, 151)])
        secrets = {"s": f"mysql://oplia_cc:{pw}@127.0.0.1:{MYSQL_PORT}/app_src",
                   "d": f"mysql://oplia_cc:{pw}@127.0.0.1:{MYSQL_PORT}/app_dr"}
        reg, checker = _checker(gate, session_factory, _specs("mysql", "app_src", "app_dr"), secrets)
        r = checker.run("dr", triggered_by="alice")
        assert r["status"] == "CONSISTENT", r
        assert r["report"]["tables"]["products"] == {"source_rows": 150, "target_rows": 150, "match": True,
                                                     "checksum": "match"}
        with conns["app_dr"].cursor() as cur:
            cur.execute("UPDATE products SET name = 'tampered' WHERE id = 120")
        r = checker.run("dr", triggered_by="alice")
        assert r["status"] == "DRIFT" and r["report"]["schema"] == []
        assert r["report"]["tables"]["products"]["checksum"] == "differ"
        gate.approve(r["proposal_id"], "bob")
        done = gate.execute(r["proposal_id"], ResyncExecutor(reg, CFG), "ops")
        assert done.status is ProposalStatus.EXECUTED, done.result
        assert done.result["tables"][0]["verified"] is True and done.result["paused_replica"] is False
        with conns["app_dr"].cursor() as cur:
            cur.execute("SELECT name FROM products WHERE id = 120")
            assert cur.fetchone()[0] == "p120"
        assert checker.run("dr", triggered_by="alice")["status"] == "CONSISTENT"
    finally:
        for c in conns.values():
            c.close()


# ----------------------------------------------------------------------------- MongoDB (fake driver)
class _Cursor(list):
    def sort(self, key, direction):
        return _Cursor(sorted(self, key=lambda d: d[key], reverse=direction < 0))


class _Coll:
    def __init__(self, docs, indexes):
        self.docs, self.indexes = docs, indexes

    def list_indexes(self):
        return [{"key": k} for k in self.indexes]

    def count_documents(self, flt):
        assert flt == {}
        return len(self.docs)

    def find(self, flt, batch_size):
        return _Cursor(self.docs)


class _Db(dict):
    def list_collection_names(self):
        return list(self.keys())


class _Mongo:
    def __init__(self, dbs):
        self.dbs = dbs

    def __getitem__(self, name):
        return self.dbs[name]

    def close(self):
        pass


def test_mongo_document_drift(gate, session_factory):
    def make(extra):
        docs = [{"_id": i, "user": f"u{i}", "n": i} for i in range(1, 20)] + extra
        return _Mongo({"app": _Db({"sessions": _Coll(docs, [{"_id": 1}, {"user": 1}]),
                                   "system.views": _Coll([], [])})})

    src, dst = make([]), make([{"_id": 99, "user": "ghost", "n": 0}])
    reg = DatabaseRegistry(_specs("mongodb", "app", "app"), StaticSecretProvider({"s": "mongodb://a", "d": "mongodb://b"}),
                           session_factory, connectors={"mongodb": lambda uri: src if uri.endswith("a") else dst})
    checker = ConsistencyChecker(reg, gate, session_factory, cfg=CFG)
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "DRIFT" and r["report"]["tables"]["sessions"] == {"source_rows": 19, "target_rows": 20,
                                                                           "match": False, "rechecked": True}
    assert "system.views" not in r["report"]["tables"]
    dst.dbs["app"]["sessions"].docs.pop()
    assert checker.run("dr", triggered_by="alice")["status"] == "CONSISTENT"


def test_api_consistency_endpoints(gate, session_factory):
    from fastapi.testclient import TestClient

    from oplia_ctl.api import create_app
    from oplia_ctl.auth import OIDCVerifier
    from tests.test_api import AUD, ISS, KEY, SECRETS, bearer

    reg = DatabaseRegistry(_specs("postgres", "x", "y"), StaticSecretProvider({"s": "postgresql://u:p@127.0.0.1:1/x",
                                                                               "d": "postgresql://u:p@127.0.0.1:1/y"}),
                           session_factory)
    client = TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=["control-tower-standard"], approver_role="oplia-approver", operator_role="oplia-operator",
        db_registry=reg, consistency=ConsistencyChecker(reg, gate, session_factory, cfg=CFG)))
    op = bearer("bob", "oplia-operator")
    assert client.post("/databases/src/consistency", headers=op).status_code == 404   # a primary, not a DR copy
    r = client.post("/databases/dr/consistency", headers=op).json()
    assert r["status"] == "FAILED" and r["pair"] == "dr"
    runs = client.get("/databases/consistency", params={"pair": "dr"}, headers=op).json()
    assert [x["status"] for x in runs] == ["FAILED"] and runs[0]["triggered_by"] == "bob"
    assert client.get("/me", headers=op).json()["features"]["consistency"] is True
