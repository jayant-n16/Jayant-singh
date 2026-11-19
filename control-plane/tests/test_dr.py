from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

import bson
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.dr.breaker import CircuitBreaker, WebhookSpec, list_incidents
from oplia_ctl.dr.decode import Mutation, Record, decode, payload_for_dump
from oplia_ctl.dr.lockers import MongoLocker, MySQLLocker, PostgresLocker, TargetSpec
from oplia_ctl.dr.relay import KafkaSink, KafkaSource, Relay
from oplia_ctl.dr.rules import RateMonitor, static_findings
from oplia_ctl.http import ResilientClient
from oplia_ctl.safety import SafetyGate
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_aiops import FakeNotifier
from tests.test_api import AUD, ISS, KEY, bearer

HOOK = "https://ops.example.com/hooks/dr"


# =================================================================== decoding
def kinds(rec: Record) -> list[tuple[str, bool]]:
    return [(m.kind, m.unconstrained) for m in decode(rec)]


@pytest.mark.parametrize(("sql", "expected"), [
    ("DROP TABLE orders", [("drop_table", False)]),
    ("drop database shop", [("drop_database", False)]),
    ("TRUNCATE TABLE orders, items", [("truncate", False)]),
    ("DELETE FROM orders", [("delete", True)]),
    ("DELETE FROM orders WHERE id = 7", [("delete", False)]),
    ("UPDATE users SET admin = true", [("update", True)]),
    ("UPDATE users SET admin = true WHERE id = 1", [("update", False)]),
    ("INSERT INTO audit(note) VALUES ('DROP TABLE x; TRUNCATE y')", [("insert", False)]),  # literal, not a command
    ("/* DROP TABLE x */ SELECT 1", [("read", False)]),
    ("BEGIN; DELETE FROM a WHERE id=1; DROP TABLE b; COMMIT", [("other", False), ("delete", False),
                                                              ("drop_table", False), ("other", False)]),
])
def test_sql_decoding(sql, expected):
    assert kinds(Record("sql", sql, "postgres")) == expected


def test_sql_mysql_dialect_and_unparseable():
    assert kinds(Record("sql", "DELETE FROM `orders`", "mysql", sql_dialect="mysql")) == [("delete", True)]
    assert kinds(Record("sql", "DROP TABLE ((((", "postgres"))[0][0] == "undecodable"


def test_debezium_envelopes():
    row = {"schema": {}, "payload": {"op": "d", "source": {"db": "shop", "table": "orders"}}}
    [m] = decode(Record("debezium", json.dumps(row).encode(), "postgres"))
    assert (m.kind, m.target, m.rows) == ("delete", "shop.orders", 1)
    assert kinds(Record("debezium", {"op": "t", "source": {"db": "shop", "table": "orders"}}, "postgres")) == [
        ("truncate", False)]
    ddl = {"source": {"db": "shop"}, "databaseName": "shop", "ddl": "DROP TABLE `orders`"}
    assert kinds(Record("debezium", ddl, "mysql")) == [("drop_table", False)]
    assert decode(Record("debezium", {"schema": {}, "payload": None}, "postgres")) == []  # tombstone
    assert kinds(Record("debezium", b"not json", "postgres"))[0][0] == "undecodable"


def test_mongo_change_stream_and_commands():
    assert kinds(Record("mongo_change", {"operationType": "dropDatabase", "ns": {"db": "shop"}}, "mongodb")) == [
        ("drop_database", False)]
    assert kinds(Record("mongo_change", {"operationType": "drop", "ns": {"db": "shop", "coll": "o"}}, "mongodb")) == [
        ("drop_table", False)]
    delete_all = bson.encode({"delete": "orders", "deletes": [{"q": {}, "limit": 0}], "$db": "shop"})
    [m] = decode(Record("mongo_command", delete_all, "mongodb"))
    assert (m.kind, m.unconstrained, m.statement, m.target) == ("delete", True, "deleteMany", "shop.orders")
    scoped = bson.encode({"delete": "orders", "deletes": [{"q": {"status": "void"}, "limit": 0}]})
    assert kinds(Record("mongo_command", scoped, "mongodb")) == [("delete", False)]
    one = bson.encode({"delete": "orders", "deletes": [{"q": {}, "limit": 1}]})
    assert kinds(Record("mongo_command", one, "mongodb")) == [("delete", False)]  # deleteOne
    upd = {"update": "users", "updates": [{"q": {}, "u": {"$set": {"admin": True}}, "multi": True}]}
    assert kinds(Record("mongo_command", json.dumps(upd), "mongodb")) == [("update", True)]
    assert kinds(Record("mongo_command", bson.encode({"dropDatabase": 1, "$db": "x"}), "mongodb")) == [
        ("drop_database", False)]
    dump = payload_for_dump(Record("mongo_command", delete_all, "mongodb"))
    assert dump["delete"] == "orders" and dump["deletes"][0]["q"] == {}


def test_crdb_changefeed_formats():
    assert kinds(Record("crdb_changefeed", {"after": None, "key": [1], "topic": "orders"}, "cockroachdb")) == [
        ("delete", False)]
    assert kinds(Record("crdb_changefeed", {"after": {"id": 1}, "key": [1]}, "cockroachdb")) == [("insert", False)]
    assert kinds(Record("crdb_changefeed", {"op": "d", "table": "orders"}, "cockroachdb")) == [("delete", False)]
    webhook_batch = {"payload": [{"after": None, "key": [1], "topic": "o"}, {"after": {"id": 2}, "key": [2]}],
                     "length": 2}
    assert [k for k, _ in kinds(Record("crdb_changefeed", webhook_batch, "cockroachdb"))] == ["delete", "insert"]
    assert decode(Record("crdb_changefeed", {"resolved": "1700000000.0000000000"}, "cockroachdb")) == []


# ====================================================================== rules
def test_static_rules():
    ms = [Mutation("postgres", "insert", "a"), Mutation("postgres", "drop_table", "orders"),
          Mutation("mysql", "update", "u", unconstrained=True, statement="UPDATE u SET x=1"),
          Mutation("mongodb", "undecodable", "", 0, detail={"error": "x"})]
    assert [f.rule for f in static_findings(ms)] == ["drop", "unconstrained_write", "undecodable"]
    assert [f.rule for f in static_findings(ms, block_undecodable=False)] == ["drop", "unconstrained_write"]


class Tick:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def rows(n: int) -> list[Mutation]:
    return [Mutation("postgres", "update", "t", rows=n)]


def test_rate_monitor_500_percent_rule():
    tick = Tick()
    rm = RateMonitor(spike_percent=500, window_seconds=60, baseline_windows=5, min_mutations=1000, clock=tick)
    for _ in range(5):  # 5 minutes of history: 1000 rows/minute
        assert rm.observe(rows(1000)) is None
        tick.t += 60
    assert rm.observe(rows(6000)) is None  # exactly 6x = +500 %: not *more than*
    tick.t = 0.0
    rm2 = RateMonitor(spike_percent=500, window_seconds=60, baseline_windows=5, min_mutations=1000, clock=tick)
    for _ in range(5):
        rm2.observe(rows(1000))
        tick.t += 60
    f = rm2.observe(rows(6001))
    assert f is not None and f.rule == "rate_spike" and f.numbers["baseline"] == 1000.0


def test_rate_monitor_warmup_and_floor():
    tick = Tick()
    rm = RateMonitor(min_mutations=1000, clock=tick)
    assert rm.observe(rows(100000)) is None  # no baseline yet
    tick.t = 0.0
    rm = RateMonitor(min_mutations=1000, clock=tick)
    for _ in range(5):
        rm.observe(rows(1))
        tick.t += 60
    assert rm.observe(rows(900)) is None  # 900x but under the volume floor


# ==================================================================== breaker
class FakeSink:
    def __init__(self):
        self.sent: list[list[Record]] = []
        self.closed = False

    def send(self, records):
        assert not self.closed
        self.sent.append(list(records))

    def close(self):
        self.closed = True


class FakeLocker:
    def __init__(self, name, fail=False):
        self.name, self.fail, self.locked, self.unlocked = name, fail, 0, []

    def lock(self):
        if self.fail:
            raise RuntimeError("access denied")
        self.locked += 1
        return {"engine": "fake", "verified_read_only": True, "token": self.name}

    def unlock(self, state):
        self.unlocked.append(state)
        return {"unlocked": True}


SECRETS = StaticSecretProvider({"hook_url": HOOK, "hook_hmac": "k3y"})


def make_breaker(gate, session_factory, tmp_path, lockers=None, notifier=None, **kw):
    return CircuitBreaker(stream="orders-pg", gate=gate, session_factory=session_factory, secrets=SECRETS,
                          client=ResilientClient(sleep=lambda _s: None, max_retries=0),
                          lockers=lockers if lockers is not None else [FakeLocker("dr-aws"), FakeLocker("dr-gcp")],
                          webhooks=[WebhookSpec(url_secret="hook_url", hmac_secret="hook_hmac")],
                          notifier=notifier if notifier is not None else FakeNotifier(),
                          quarantine_dir=str(tmp_path / "q"), **kw)


BAD = [Record("sql", "UPDATE accounts SET balance = 0", "postgres", position="cdc:0:41"),
       Record("debezium", {"op": "u", "source": {"db": "bank", "table": "accounts"}}, "postgres", position="cdc:0:42")]


@respx.mock
def test_trip_severs_dumps_alerts_and_locks(gate, session_factory, tmp_path):
    hook = respx.post(HOOK).mock(return_value=httpx.Response(204))
    notifier = FakeNotifier()
    lockers = [FakeLocker("dr-aws"), FakeLocker("dr-ibm", fail=True)]
    b = make_breaker(gate, session_factory, tmp_path, lockers=lockers, notifier=notifier)
    res = b.inspect(BAD)
    assert [f.rule for f in res.findings] == ["unconstrained_write"]
    sink = FakeSink()
    incident = b.trip(BAD, res.findings, sink)

    assert sink.closed and sink.sent == []                                   # A
    assert b.store.state("orders-pg")[:2] == ("OPEN", incident)
    body = hook.calls.last.request.content                                   # B: full dump, signed
    dump = json.loads(body)
    assert dump["records"][0]["payload"] == "UPDATE accounts SET balance = 0"
    assert dump["records"][1]["payload"]["source"]["table"] == "accounts"
    ts = hook.calls.last.request.headers["X-OPLIA-Timestamp"]
    expected = hmac.new(b"k3y", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert hook.calls.last.request.headers["X-OPLIA-Signature"] == f"sha256={expected}"
    inc = list_incidents(session_factory)[0]
    assert inc["dump_sha256"] == hashlib.sha256(body).hexdigest()
    assert Path(inc["dump_path"]).read_bytes() == body                      # durable copy, identical
    assert oct(os.stat(inc["dump_path"]).st_mode & 0o777) == "0o600"
    page = notifier.sent[0][0]
    assert page.severity == "critical" and page.details["dump_sha256"] == inc["dump_sha256"]
    assert inc["actions"]["locks"]["dr-aws"]["ok"] is True                  # C
    assert inc["actions"]["locks"]["dr-ibm"] == {"ok": False, "error": "RuntimeError: access denied"}
    assert inc["positions"] == ["cdc:0:41", "cdc:0:42"]
    assert gate.verify_audit_chain()


@respx.mock
def test_trip_survives_failing_webhook_and_dry_run_does_not_lock(session_factory, clock, tmp_path):
    respx.post(HOOK).mock(return_value=httpx.Response(500))
    dry = SafetyGate(session_factory, dry_run=True, require_approval=True, four_eyes=True, clock=clock)
    locker = FakeLocker("dr-aws")
    b = make_breaker(dry, session_factory, tmp_path, lockers=[locker])
    b.trip(BAD, b.inspect(BAD).findings, FakeSink())
    inc = list_incidents(session_factory)[0]
    assert inc["actions"]["webhooks"] == {"webhook-0": "failed: HttpError 500"}
    assert inc["actions"]["locks"]["dr-aws"]["dry_run"] is True and locker.locked == 0
    assert HOOK not in json.dumps(inc)  # the URL (a credential) is never stored


@respx.mock
def test_reset_unlocks_only_what_was_locked(gate, session_factory, tmp_path):
    respx.post(HOOK).mock(return_value=httpx.Response(204))
    good, bad = FakeLocker("dr-aws"), FakeLocker("dr-ibm", fail=True)
    b = make_breaker(gate, session_factory, tmp_path, lockers=[good, bad])
    b.trip(BAD, b.inspect(BAD).findings, FakeSink())
    out = b.reset(actor="dave", decision="discard", unlock_targets=True, note="false positive, ticket 42")
    assert good.unlocked == [{"ok": True, "engine": "fake", "verified_read_only": True, "token": "dr-aws"}]
    assert out["unlocked"]["dr-ibm"] == {"skipped": "was not locked by this incident"}
    assert b.store.state("orders-pg") == ("CLOSED", out["incident_id"], "discard")
    with pytest.raises(ValueError, match="CLOSED"):
        b.reset(actor="dave", decision="discard", unlock_targets=False, note="again please")


# ====================================================================== relay
class ListSource:
    def __init__(self, bundles):
        self.bundles = list(bundles)
        self.committed: list[str] = []
        self.closed = False

    def poll_bundle(self, timeout):
        return self.bundles.pop(0) if self.bundles else []

    def commit(self, bundle):
        self.committed += [r.position for r in bundle]

    def close(self):
        self.closed = True


GOOD = [Record("sql", "UPDATE a SET x = 1 WHERE id = 1", "postgres", position="cdc:0:1")]


@respx.mock
def test_relay_forwards_holds_and_releases(gate, session_factory, tmp_path):
    respx.post(HOOK).mock(return_value=httpx.Response(204))
    sinks: list[FakeSink] = []

    def factory():
        sinks.append(FakeSink())
        return sinks[-1]

    src = ListSource([GOOD, BAD, [Record("sql", "SELECT 1", "postgres", position="cdc:0:43")]])
    b = make_breaker(gate, session_factory, tmp_path)
    relay = Relay(breaker=b, source=src, sink_factory=factory, session_factory=session_factory)
    assert relay.step() == "forwarded" and src.committed == ["cdc:0:1"]
    assert relay.step() == "tripped"
    assert sinks[0].closed and src.committed == ["cdc:0:1"]           # violating bundle neither sent nor committed
    assert relay.step() == "open" and relay.step() == "open"          # stays stopped
    b.reset(actor="dave", decision="release", unlock_targets=False, note="reviewed: intended migration")
    assert relay.step() == "released"
    assert sinks[-1].sent == [BAD] and src.committed[-2:] == ["cdc:0:41", "cdc:0:42"]
    assert relay.step() == "forwarded"


@respx.mock
def test_relay_restart_while_open_applies_decision_by_position(gate, session_factory, tmp_path):
    respx.post(HOOK).mock(return_value=httpx.Response(204))
    b = make_breaker(gate, session_factory, tmp_path)
    first = Relay(breaker=b, source=ListSource([BAD]), sink_factory=FakeSink, session_factory=session_factory)
    assert first.step() == "tripped"
    # process restarts; Kafka re-delivers from the last commit in a *different* batch shape
    later = Record("sql", "INSERT INTO a VALUES (1)", "postgres", position="cdc:0:43")
    src = ListSource([[BAD[0]], [BAD[1], later]])
    sinks: list[FakeSink] = []
    second = Relay(breaker=b, source=src, sink_factory=lambda: sinks.append(FakeSink()) or sinks[-1],
                   session_factory=session_factory)
    assert second.step() == "open" and sinks[0].closed       # sees OPEN at start-up: stays severed
    b.reset(actor="dave", decision="discard", unlock_targets=False, note="corrupt batch, dropped")
    assert second.step() == "discarded" and src.committed == ["cdc:0:41"]
    assert second.step() == "forwarded"  # cdc:0:42 discarded, cdc:0:43 inspected and forwarded
    assert src.committed == ["cdc:0:41", "cdc:0:42", "cdc:0:43"]
    assert [x for s in sinks for x in s.sent] == [[later]]  # nothing of the incident reached the DR side


def test_relay_severs_on_manual_trip_from_api(gate, session_factory, tmp_path):
    b = make_breaker(gate, session_factory, tmp_path, lockers=[], notifier=FakeNotifier())
    b._webhooks = []
    sink = FakeSink()
    relay = Relay(breaker=b, source=ListSource([GOOD]), sink_factory=lambda: sink, session_factory=session_factory)
    b.store.set("orders-pg", "OPEN", "dave", None)
    assert relay.step() == "open" and sink.closed


# ======================================================= Kafka adapter (fakes)
class FakeMsg:
    def __init__(self, value, offset, err=None):
        self._v, self._o, self._e = value, offset, err

    def error(self):
        return self._e

    def value(self):
        return self._v

    def topic(self):
        return "cdc.public.orders"

    def partition(self):
        return 3

    def offset(self):
        return self._o


class FakeConsumer:
    def __init__(self, msgs):
        self.msgs, self.commits, self.subscribed = msgs, [], None

    def subscribe(self, topics):
        self.subscribed = topics

    def consume(self, num_messages, timeout):
        out, self.msgs = self.msgs[:num_messages], self.msgs[num_messages:]
        return out

    def commit(self, offsets, asynchronous):
        self.commits.append(([(o.topic, o.partition, o.offset) for o in offsets], asynchronous))

    def close(self):
        pass


def test_kafka_source_positions_and_commit():
    c = FakeConsumer([FakeMsg(b'{"op":"c"}', 10), FakeMsg(None, 11), FakeMsg(b'{"op":"u"}', 12)])
    src = KafkaSource(config={}, topics=["cdc.public.orders"], fmt="debezium", engine="postgres", consumer=c)
    bundle = src.poll_bundle(1.0)
    assert [r.position for r in bundle] == ["cdc.public.orders:3:10", "cdc.public.orders:3:12"]
    src.commit(bundle)
    assert c.commits == [([("cdc.public.orders", 3, 13)], False)]  # next offset, synchronous


class FakeProducer:
    def __init__(self, cfg, fail=False):
        self.cfg, self.fail, self.produced, self.purged = cfg, fail, [], False

    def produce(self, topic, value, on_delivery):
        self.produced.append((topic, value))
        on_delivery("broker down" if self.fail else None, None)

    def flush(self, timeout):
        return 0

    def purge(self, in_queue, in_flight):
        self.purged = True


def test_kafka_sink_acks_and_sever():
    made = []
    sink = KafkaSink(config={"bootstrap.servers": "k:9093"}, topic="dr.orders",
                     producer_factory=lambda cfg: made.append(FakeProducer(cfg)) or made[-1])
    assert made[0].cfg["enable.idempotence"] is True and made[0].cfg["acks"] == "all"
    sink.send([Record("debezium", {"op": "c"}, "postgres")])
    assert made[0].produced == [("dr.orders", b'{"op": "c"}')]
    sink.close()
    assert made[0].purged
    with pytest.raises(RuntimeError, match="severed"):
        sink.send(GOOD)
    failing = KafkaSink(config={}, topic="t", producer_factory=lambda cfg: FakeProducer(cfg, fail=True))
    with pytest.raises(RuntimeError, match="did not acknowledge"):
        failing.send(GOOD)


# ======================================================= lockers vs real servers
PG_URL = os.environ.get("OPLIA_TEST_DATABASE_URL", "")


@pytest.mark.skipif(not PG_URL, reason="needs PostgreSQL (OPLIA_TEST_DATABASE_URL)")
def test_postgres_locker_against_real_server():
    import psycopg

    admin = PG_URL.replace("postgresql+psycopg://", "postgresql://")
    base = admin.rsplit("/", 1)[0]
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS oplia_dr_target WITH (FORCE)")
        c.execute("CREATE DATABASE oplia_dr_target")
    target = f"{base}/oplia_dr_target"
    victim = psycopg.connect(target, autocommit=True)  # an open session that must be cut
    locker = PostgresLocker(TargetSpec(name="dr-pg", engine="postgres", cloud="aws", dsn_secret="dsn",
                                       database="oplia_dr_target"), StaticSecretProvider({"dsn": target}))
    state = locker.lock()
    assert state["verified_read_only"] is True and state["terminated_sessions"] >= 1
    with pytest.raises(psycopg.OperationalError):
        victim.execute("SELECT 1")
    with psycopg.connect(target, autocommit=True) as c, pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        c.execute("CREATE TABLE t (id int)")
    assert locker.unlock(state)["read_only"] == "off"
    with psycopg.connect(target, autocommit=True) as c:
        c.execute("CREATE TABLE t (id int)")
    wrong = PostgresLocker(TargetSpec(name="dr-pg", engine="postgres", cloud="aws", dsn_secret="dsn",
                                      database="other_db"), StaticSecretProvider({"dsn": target}))
    with pytest.raises(ValueError, match="expected 'other_db'"):
        wrong.lock()


MYSQL_PORT = os.environ.get("OPLIA_TEST_MYSQL_PORT", "")


@pytest.mark.skipif(not MYSQL_PORT, reason="needs MySQL (scripts/test-mysql.sh)")
def test_mysql_locker_against_real_server():
    import pymysql

    pw = os.environ["OPLIA_TEST_MYSQL_PW"]
    dsn = f"mysql://oplia_dr:{pw}@127.0.0.1:{MYSQL_PORT}/"
    locker = MySQLLocker(TargetSpec(name="dr-mysql", engine="mysql", cloud="azure", dsn_secret="dsn"),
                         StaticSecretProvider({"dsn": dsn}))
    state = locker.lock()
    assert state == {"engine": "mysql", "stopped_replica": False, "verified_read_only": True}
    app = pymysql.connect(host="127.0.0.1", port=int(MYSQL_PORT), user="app", password=pw, database="app",
                          autocommit=True)
    try:
        with app.cursor() as cur, pytest.raises(pymysql.err.OperationalError, match="read-only"):
            cur.execute("CREATE TABLE t (id int)")
        assert locker.unlock(state)["super_read_only"] == 0
        with app.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS t (id int)")
            cur.execute("DROP TABLE t")
    finally:
        app.close()


class FakeAdmin:
    def __init__(self):
        self.calls = []

    def command(self, name, **kw):
        self.calls.append((name, kw))
        return {"lockCount": 1, "ok": 1} if name == "fsync" else {"lockCount": 0, "ok": 1}


class FakeMongo:
    def __init__(self):
        self.admin = FakeAdmin()
        self.closed = False

    def close(self):
        self.closed = True


def test_mongo_locker_uses_fsync_lock():
    m = FakeMongo()
    lk = MongoLocker(TargetSpec(name="dr-mongo", engine="mongodb", cloud="gcp", dsn_secret="u"),
                     StaticSecretProvider({"u": "mongodb://x"}), client_factory=lambda _u: m)
    st = lk.lock()
    assert m.admin.calls == [("fsync", {"lock": True})] and st["lock_count"] == 1 and m.closed
    assert lk.unlock(st) == {"engine": "mongodb", "lock_count": 0}


# ======================================================================== API
@respx.mock
def test_api_dr_endpoints(gate, session_factory, tmp_path):
    respx.post(HOOK).mock(return_value=httpx.Response(204))
    b = make_breaker(gate, session_factory, tmp_path)
    app = create_app(
        gate=gate, secrets=StaticSecretProvider({}),
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="w", webhook_max_skew_seconds=300, allowed_blueprints=[],
        approver_role="oplia-approver", operator_role="oplia-operator", dr_breaker=b)
    c = TestClient(app)
    op, ap = bearer("carol", "oplia-operator"), bearer("dave", "oplia-approver")
    assert c.get("/dr/breakers", headers=op).json()[0]["state"] == "CLOSED"
    assert c.post("/dr/breakers/orders-pg/trip", json={"reason": "suspicious"}, headers=op).status_code == 403
    assert c.post("/dr/breakers/nope/trip", json={"reason": "suspicious"}, headers=ap).status_code == 404
    r = c.post("/dr/breakers/orders-pg/trip", json={"reason": "ransomware alert from SOC"}, headers=ap)
    assert r.status_code == 200 and r.json()["state"] == "OPEN"
    assert c.post("/dr/breakers/orders-pg/trip", json={"reason": "again!"}, headers=ap).status_code == 409
    inc = c.get("/dr/incidents", headers=op).json()[0]
    assert inc["trigger"] == "manual" and inc["actions"]["locks"]["dr-aws"]["ok"] is True
    rs = c.post("/dr/breakers/orders-pg/reset", json={"decision": "discard", "unlock_targets": True,
                                                      "note": "SOC cleared"}, headers=ap)
    assert rs.status_code == 200 and rs.json()["unlocked"]["dr-aws"]["ok"] is True
    assert c.post("/dr/breakers/orders-pg/reset", json={"decision": "release", "note": "again"},
                  headers=ap).status_code == 409


def test_text_helper_handles_all_binary_types():
    from oplia_ctl.dr.lockers import _text

    samples = [b"orders", bytearray(b"orders"), memoryview(b"orders"), "orders"]
    assert {_text(v) for v in samples} == {"orders"}
