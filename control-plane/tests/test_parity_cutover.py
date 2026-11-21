"""FR-05 parity (real PostgreSQL and MySQL, including PostgreSQL vs MySQL) and FR-06 cutover/failback through a
real Envoy binary (OPLIA_TEST_ENVOY_BIN; CI downloads Envoy 1.34.4 and checks the published SHA-256)."""

from __future__ import annotations

import json
import os
import socket
import socketserver
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from oplia_ctl.databases.registry import DatabaseRegistry, DatabaseSpec
from oplia_ctl.http import ResilientClient
from oplia_ctl.migration.cutover import (
    Cutover,
    CutoverSettings,
    EnvoyRouter,
    Failback,
    ProxySettings,
    bootstrap,
    lds,
)
from oplia_ctl.migration.parity import (
    ParityCheck,
    compare_documents,
    compare_exact,
    compare_shape,
    compare_vectors,
    norm,
)
from oplia_ctl.secrets import StaticSecretProvider

PG_URL = os.environ.get("OPLIA_TEST_DATABASE_URL", "").replace("postgresql+psycopg://", "postgresql://")
MYSQL_PORT = os.environ.get("OPLIA_TEST_MYSQL_PORT", "")
ENVOY = os.environ.get("OPLIA_TEST_ENVOY_BIN", "")


def test_normalisation_is_engine_neutral():
    assert norm(True) == norm(1) == 1
    assert norm(Decimal("12.50")) == norm(Decimal("12.5")) == norm("12.50") == "12.5"
    t = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert norm(t) == norm(t.astimezone(UTC).replace(tzinfo=None)) == "2026-01-01T12:00:00"
    assert norm(b"\x01") == "01" and norm(None) is None and norm("abc") == "abc"


def test_document_shape_and_vector_parity():
    rows = [{"id": 1, "total": Decimal("2.50")}, {"id": 2, "total": Decimal("3")}]
    docs = {"1": {"_id": "1", "id": 1, "total": "2.5"}, "2": {"_id": "2", "id": 2, "total": "4"}}
    r = compare_documents(iter(rows), docs.get, lambda x: str(x["id"]))
    assert r["status"] == "DIFF" and r["changed"] == ["2"] and r["missing_on_target"] == []
    assert compare_shape([{"a": 1, "b": "x"}] * 5, [{"a": 1, "b": "x"}] * 5)["status"] == "MATCH"
    s = compare_shape([{"a": 1, "b": "x"}] * 5, [{"a": "1"}] * 5)
    assert s["fields_only_on_source"] == ["b"] and "a" in s["type_drift"]
    v = compare_vectors([("k1", [1.0, 0.0], [0.99, 0.01]), ("k2", [1.0, 0.0], [0.0, 1.0])])
    assert v["status"] == "DIFF" and v["below_threshold"][0]["key"] == "k2"


def _pg_db(name):
    import psycopg

    base = PG_URL.rsplit("/", 1)[0]
    with psycopg.connect(PG_URL, autocommit=True) as c:
        c.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        c.execute(f"CREATE DATABASE {name}")
    return f"{base}/{name}"


@pytest.mark.skipif(not PG_URL, reason="needs PostgreSQL (OPLIA_TEST_DATABASE_URL)")
def test_exact_parity_job_finds_the_changed_rows(gate, session_factory):
    import psycopg

    dsns = {n: _pg_db(n) for n in ("par_src", "par_dst")}
    for dsn in dsns.values():
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute("CREATE TABLE orders (id int PRIMARY KEY, sku text COLLATE \"C\", total numeric(10,2), "
                      "at timestamptz, ok boolean)")
            c.execute("INSERT INTO orders SELECT g, 'sku' || g, g * 1.25, '2026-01-01'::timestamptz + g * "
                      "interval '1 hour', g % 2 = 0 FROM generate_series(1, 3000) g")
    reg = DatabaseRegistry([DatabaseSpec(name="src", engine="postgres", cloud="aws", role="primary", dsn_secret="s"),
                            DatabaseSpec(name="dst", engine="postgres", cloud="gcp", role="replica", dr_of="src",
                                         dsn_secret="d")],
                           StaticSecretProvider({"s": dsns["par_src"], "d": dsns["par_dst"]}), session_factory)
    events = []
    m = ParityCheck(reg, session_factory, audit=lambda e, d: events.append((e, d["status"])))
    jid = m(m.parse({"source": "src", "target": "dst"}))["job_id"]
    m.run_pending()
    j = m.get(jid)
    assert j["status"] == "SUCCEEDED" and j["state"]["result"]["tables"]["orders"]["source_rows"] == 3000
    with psycopg.connect(dsns["par_dst"], autocommit=True) as c:
        c.execute("UPDATE orders SET total = 0 WHERE id = 1500")
        c.execute("DELETE FROM orders WHERE id = 42")
        c.execute("INSERT INTO orders VALUES (9999, 'x', 1, now(), true)")
    jid = m(m.parse({"source": "src", "target": "dst"}))["job_id"]
    m.run_pending()
    j = m.get(jid)
    t = j["state"]["result"]["tables"]["orders"]
    # a completed comparison SUCCEEDS; the verdict is the result (FAILED only when it cannot run)
    assert j["status"] == "SUCCEEDED" and j["error"] is None and j["state"]["result"]["status"] == "DIFF"
    assert (t["changed"], t["missing_on_target"], t["extra_on_target"]) == ([[1500]], [[42]], [[9999]])
    assert t["status"] == "DIFF" and t["rows_match"] is False
    assert events == [("migration.parity_check.succeeded", "MATCH"), ("migration.parity_check.succeeded", "DIFF")]

    # a column the target lacks is a schema difference (it was compared out silently before)
    with psycopg.connect(dsns["par_dst"], autocommit=True) as c:
        c.execute("UPDATE orders SET total = 1500 * 1.25 WHERE id = 1500")
        c.execute("INSERT INTO orders SELECT 42, 'sku42', 42 * 1.25, "
                  "'2026-01-01'::timestamptz + 42 * interval '1 hour', true")
        c.execute("DELETE FROM orders WHERE id = 9999")
    with psycopg.connect(dsns["par_src"], autocommit=True) as c:
        c.execute("ALTER TABLE orders ADD COLUMN total__oplia_new numeric(14,2)")
    jid = m(m.parse({"source": "src", "target": "dst"}))["job_id"]
    m.run_pending()
    r = m.get(jid)["state"]["result"]
    assert m.get(jid)["status"] == "SUCCEEDED" and r["status"] == "DIFF"
    assert r["schema"] == [{"table": "orders", "issue": "columns not on target", "columns": ["total__oplia_new"]}]
    o = r["tables"]["orders"]
    assert o["columns_not_on_target"] == ["total__oplia_new"] and o["rows_match"] is True and o["status"] == "DIFF"

    # the comparison itself failing (target database unreachable) is what FAILED means
    bad = StaticSecretProvider({"s": dsns["par_src"], "d": dsns["par_dst"].rsplit("/", 1)[0] + "/no_such_db_xyz"})
    reg._secrets = bad
    jid = m(m.parse({"source": "src", "target": "dst"}))["job_id"]
    m.run_pending()
    assert m.get(jid)["status"] == "FAILED"


def test_cutover_refuses_a_succeeded_parity_job_with_a_diff_verdict(session_factory, tmp_path):
    cfg = ProxySettings(config_dir=str(tmp_path / "envoy"), clusters={"a": {"host": "db1", "port": 5432},
                                                                     "b": {"host": "db2", "port": 5432}},
                        listeners=[{"name": "ro", "port": 6432, "legacy": "a", "new": "b", "writes": False}])

    class NoTraffic:
        def __getattr__(self, name):
            raise AssertionError(f"the router must not be touched ({name})")

    lag = {"status": "SUCCEEDED", "state": {"result": {"p99_ms": 120.0, "not_arrived_within_timeout": 0}}}
    par = {"status": "SUCCEEDED", "state": {"result": {"status": "DIFF", "schema": [], "tables": {}}}}
    jobs = {("cdc_lag_probe", "1" * 36): lag, ("parity_check", "2" * 36): par}
    m = Cutover(CutoverSettings(proxy=cfg), session_factory, NoTraffic(), lambda k, j: jobs[(k, j)])
    jid = m(m.parse({"listener": "ro", "spec": {"lag_job": "1" * 36, "parity_job": "2" * 36}}))["job_id"]
    m.run_pending()
    j = m.get(jid)
    assert j["status"] == "FAILED" and "parity evidence not MATCH" in j["error"]
    assert j["state"]["precheck"]["problems"] == ["parity evidence not MATCH: SUCCEEDED"]


@pytest.mark.skipif(not (PG_URL and MYSQL_PORT), reason="needs PostgreSQL and MySQL")
def test_exact_parity_across_postgres_and_mysql():
    import psycopg
    import pymysql

    dsn = _pg_db("par_x")
    rows = [(i, f"name {i}", Decimal(i) / 4, datetime(2026, 3, 1, 8, 0) + timedelta(minutes=i), i % 3 == 0)
            for i in range(1, 801)]
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("CREATE TABLE items (id int PRIMARY KEY, name varchar(40), price numeric(10,2), "
                  "added timestamp, active boolean)")
        with c.cursor() as cur:
            cur.executemany("INSERT INTO items VALUES (%s, %s, %s, %s, %s)", rows)
    my = pymysql.connect(host="127.0.0.1", port=int(MYSQL_PORT), user="oplia_cc",
                         password=os.environ["OPLIA_TEST_MYSQL_PW"], database="app_dr", autocommit=True)
    try:
        with my.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS items")
            cur.execute("CREATE TABLE items (id INT PRIMARY KEY, name VARCHAR(40), price DECIMAL(10,2), "
                        "added DATETIME(6), active TINYINT(1))")
            cur.executemany("INSERT INTO items VALUES (%s, %s, %s, %s, %s)", rows)
        with psycopg.connect(dsn, autocommit=True) as pg:
            r = compare_exact((pg, "postgres", None), (my, "mysql", "app_dr"), ["items"])
            assert r["status"] == "MATCH", r
            with my.cursor() as cur:
                cur.execute("UPDATE items SET active = 1 WHERE id = 1")
            r = compare_exact((pg, "postgres", None), (my, "mysql", "app_dr"), ["items"])
            assert r["tables"]["items"]["changed"] == [[1]]
    finally:
        with my.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS items")
        my.close()


# ----------------------------------------------------------------------------- Envoy
class Banner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.server.banner)     # type: ignore[attr-defined]


def _banner_server(text):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Banner)
    srv.banner = text.encode()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _read(port):
    with socket.create_connection(("127.0.0.1", port), 2) as c:
        return c.recv(16).decode()


@pytest.fixture
def envoy(tmp_path):
    if not ENVOY:
        pytest.skip("needs an Envoy binary (OPLIA_TEST_ENVOY_BIN)")
    legacy, new = _banner_server("LEGACY"), _banner_server("NEW")
    lp, ap = _free_port(), _free_port()
    cfg = ProxySettings(config_dir=str(tmp_path / "envoy"), admin_url=f"http://127.0.0.1:{ap}",
                        bind_address="127.0.0.1", drain_seconds=0,
                        clusters={"legacy": {"host": "127.0.0.1", "port": legacy.server_address[1]},
                                  "new": {"host": "127.0.0.1", "port": new.server_address[1]}},
                        listeners=[{"name": "orders_rw", "port": lp, "legacy": "legacy", "new": "new"}])
    router = EnvoyRouter(cfg, ResilientClient(timeout=5, max_retries=0))
    router.write_initial()
    boot = f"{cfg.config_dir}/bootstrap.json"
    val = subprocess.run([ENVOY, "--mode", "validate", "-c", boot], capture_output=True, text=True, timeout=60)
    assert val.returncode == 0, val.stdout + val.stderr
    proc = subprocess.Popen([ENVOY, "-c", boot, "--log-level", "warn", "--base-id", str(ap)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        try:
            if router.active_version("orders_rw") == "1" and router.routes("orders_rw") == {"legacy": 100}:
                break
        except Exception:  # noqa: S110 - Envoy admin not up yet
            pass
        time.sleep(0.1)
    yield cfg, router, lp
    proc.terminate()
    proc.wait(10)
    legacy.shutdown()
    new.shutdown()


def test_generated_envoy_config_shapes(tmp_path):
    cfg = ProxySettings(config_dir=str(tmp_path), clusters={"a": {"host": "db1", "port": 5432},
                                                            "b": {"host": "db2", "port": 5432}},
                        listeners=[{"name": "ro", "port": 6432, "legacy": "a", "new": "b", "writes": False}])
    tcp = lds(cfg, {"ro": {"a": 90, "b": 10}}, "v1")["resources"][0]["filter_chains"][0]["filters"][0]["typed_config"]
    assert tcp["weighted_clusters"]["clusters"] == [{"name": "a", "weight": 90}, {"name": "b", "weight": 10}]
    assert bootstrap(cfg)["dynamic_resources"]["lds_config"]["path_config_source"]["watched_directory"]["path"] == \
        f"{tmp_path}/lds"
    with pytest.raises(ValueError):
        ProxySettings(config_dir="/x", admin_url="http://10.0.0.1:9901", clusters={}, listeners=cfg.listeners)


def test_cutover_and_failback_through_real_envoy(envoy, session_factory):
    cfg, router, port = envoy
    assert _read(port) == "LEGACY"
    lag = {"status": "SUCCEEDED", "state": {"result": {"p99_ms": 120.0, "not_arrived_within_timeout": 0}}}
    par = {"status": "SUCCEEDED", "state": {"result": {"status": "MATCH"}}}
    jobs = {("cdc_lag_probe", "1" * 36): lag, ("parity_check", "2" * 36): par}

    class KC:
        def __init__(self):
            self.calls = []

        def act(self, n, a):
            self.calls.append(("act", n, a))

        def put_config(self, n, c):
            self.calls.append(("put", n, c))

    kc = KC()
    cs = CutoverSettings(proxy=cfg)
    events = []
    m = Cutover(cs, session_factory, router, lambda k, j: jobs[(k, j)], kafka_connect=kc,
                audit=lambda e, d: events.append(e))
    with pytest.raises(ValueError, match="one step"):
        m.parse({"listener": "orders_rw", "spec": {"lag_job": "1" * 36, "parity_job": "2" * 36, "stages": [50, 100]}})
    spec = {"lag_job": "1" * 36, "parity_job": "2" * 36, "forward_connector": "shop-cdc",
            "reverse_connector": {"name": "shop-reverse", "config": {"connector.class": "x"}}}
    jid = m(m.parse({"listener": "orders_rw", "spec": json.dumps(spec)}))["job_id"]
    for _ in range(6):
        m.run_pending()
    j = m.get(jid)
    assert j["status"] == "SUCCEEDED", (j["error"], j["state"])
    assert _read(port) == "NEW"
    assert kc.calls == [("act", "shop-cdc", "pause"), ("put", "shop-reverse", {"connector.class": "x"})]
    print("cutover applied in", j["state"]["shifts"][0]["applied_ms"], "ms")
    fb = Failback(cs, session_factory, router, kafka_connect=kc)
    fid = fb(fb.parse({"listener": "orders_rw", "slo_ms": 5000, "reverse_connector": "shop-reverse"}))["job_id"]
    fb.run_pending()
    r = fb.get(fid)["state"]["result"]
    print("failback measured:", r)
    assert _read(port) == "LEGACY" and r["verdict"] in ("MEETS SLO", "MISSES SLO") and r["applied_ms"] > 0
    assert events == ["migration.cutover.succeeded"]
    bad = {**lag, "state": {"result": {"p99_ms": 900.0, "not_arrived_within_timeout": 0}}}
    jobs[("cdc_lag_probe", "1" * 36)] = bad
    jid = m(m.parse({"listener": "orders_rw", "spec": spec}))["job_id"]
    m.run_pending()
    assert m.get(jid)["status"] == "FAILED" and "lag evidence" in m.get(jid)["error"]
    assert _read(port) == "LEGACY"          # refused before touching traffic
