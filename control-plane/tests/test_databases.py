from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.databases.registry import DatabaseRegistry, DatabaseSpec, validate_registry
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer

PG_URL = os.environ.get("OPLIA_TEST_DATABASE_URL", "")
MYSQL_PORT = os.environ.get("OPLIA_TEST_MYSQL_PORT", "")


def spec(**kw):
    base = {"name": "orders-pg", "engine": "postgres", "cloud": "aws", "role": "primary", "dsn_secret": "dsn"}
    return DatabaseSpec(**(base | kw))


def test_registry_validation():
    with pytest.raises(ValueError, match="unique"):
        validate_registry([spec(), spec()])
    with pytest.raises(ValueError, match="not a configured database"):
        validate_registry([spec(name="dr-1", role="dr", dr_of="missing")])
    with pytest.raises(ValueError, match="cannot be a copy"):
        validate_registry([spec(), spec(name="dr-1", engine="mongodb", role="dr", dr_of="orders-pg")])
    ok = validate_registry([spec(), spec(name="dr-1", engine="cockroachdb", role="dr", dr_of="orders-pg")])
    assert set(ok) == {"orders-pg", "dr-1"}
    with pytest.raises(ValueError):
        spec(database="x; DROP")
    assert "dsn_secret" not in spec().public()


def test_failed_check_never_leaks_the_dsn(session_factory):
    dsn = "postgresql://admin:Sup3r-S3cret@db.internal:5432/orders"

    def boom(d):
        raise RuntimeError(f"could not connect to {d} (password=Sup3r-S3cret)")

    reg = DatabaseRegistry([spec()], StaticSecretProvider({"dsn": dsn}), session_factory,
                           connectors={"postgres": boom})
    r = reg.check("orders-pg", triggered_by="alice")
    assert r["ok"] is False and "Sup3r-S3cret" not in r["error"] and "<dsn>" in r["error"]
    last = reg.latest()[0]["last_check"]
    assert last["ok"] is False and "Sup3r-S3cret" not in last["error"]


@pytest.mark.skipif(not PG_URL, reason="needs PostgreSQL (OPLIA_TEST_DATABASE_URL)")
def test_postgres_health_against_real_server(session_factory):
    dsn = PG_URL.replace("postgresql+psycopg://", "postgresql://")
    reg = DatabaseRegistry([spec()], StaticSecretProvider({"dsn": dsn}), session_factory)
    r = reg.check("orders-pg", triggered_by="alice")
    assert r["ok"] is True, r["error"]
    assert r["detail"]["version"].startswith("PostgreSQL 16")
    assert r["detail"]["role"] == "primary" and r["detail"]["read_only"] is False
    assert r["detail"]["replication"] == {"streaming_replicas": [], "enabled_subscriptions": []}


@pytest.mark.skipif(not MYSQL_PORT, reason="needs MySQL (scripts/test-mysql.sh)")
def test_mysql_health_against_real_server(session_factory):
    dsn = f"mysql://oplia_dr:{os.environ['OPLIA_TEST_MYSQL_PW']}@127.0.0.1:{MYSQL_PORT}/"
    reg = DatabaseRegistry([spec(name="dr-mysql", engine="mysql", cloud="azure")],
                           StaticSecretProvider({"dsn": dsn}), session_factory)
    r = reg.check("dr-mysql", triggered_by="scheduler")
    assert r["ok"] is True, r["error"]
    assert r["detail"]["version"].startswith("8.") and r["detail"]["role"] == "primary"


class FakeMongoAdmin:
    def command(self, name):
        now = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
        return {"buildInfo": {"version": "7.0.14"},
                "hello": {"isWritablePrimary": False, "secondary": True, "setName": "rs0"},
                "replSetGetStatus": {"members": [
                    {"stateStr": "PRIMARY", "optimeDate": now},
                    {"stateStr": "SECONDARY", "self": True, "optimeDate": now - timedelta(seconds=3)}]}}[name]


class FakeMongo:
    admin = FakeMongoAdmin()

    def close(self):
        pass


def test_mongo_secondary_lag(session_factory):
    reg = DatabaseRegistry([spec(name="dr-mongo", engine="mongodb", role="dr", dr_of=None)],
                           StaticSecretProvider({"dsn": "mongodb://x"}), session_factory,
                           connectors={"mongodb": lambda _d: FakeMongo()})
    r = reg.check("dr-mongo", triggered_by="t")
    assert r["detail"] == {"version": "7.0.14", "read_only": True, "role": "secondary",
                           "replication": {"set_name": "rs0", "lag_seconds": 3.0}}


class FakeCur:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0]

    def fetchall(self):
        return self.rows


class FakeCrdb:
    def execute(self, sql):
        if sql == "SELECT version()":
            return FakeCur([("CockroachDB CCL v24.2.4",)])
        if sql.startswith("SHOW default_transaction_read_only"):
            return FakeCur([("off",)])
        assert "SHOW CHANGEFEED JOBS" in sql
        import time
        return FakeCur([(101, "running", str(int((time.time() - 2) * 1e9)) + ".0000000000")])

    def close(self):
        pass


def test_cockroach_changefeed_lag(session_factory):
    reg = DatabaseRegistry([spec(name="crdb", engine="cockroachdb")], StaticSecretProvider({"dsn": "postgresql://x"}),
                           session_factory, connectors={"cockroachdb": lambda _d: FakeCrdb()})
    d = reg.check("crdb", triggered_by="t")["detail"]
    feed = d["replication"]["changefeeds"][0]
    assert d["role"] == "cluster" and feed["status"] == "running" and 1.5 < feed["lag_seconds"] < 10


def test_api_lists_and_checks_with_audit(gate, session_factory):
    reg = DatabaseRegistry([spec()], StaticSecretProvider({"dsn": "postgresql://u:pw@h/db"}), session_factory,
                           connectors={"postgres": lambda _d: (_ for _ in ()).throw(OSError("refused"))})
    client = TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=["control-tower-standard"], approver_role="oplia-approver", operator_role="oplia-operator",
        db_registry=reg))
    op = bearer("bob", "oplia-operator")
    assert client.get("/databases").status_code == 401
    assert client.get("/databases", headers=bearer("dave")).status_code == 403
    listed = client.get("/databases", headers=op).json()
    assert listed[0]["name"] == "orders-pg" and listed[0]["last_check"] is None and "dsn_secret" not in listed[0]
    assert client.post("/databases/nope/check", headers=op).status_code == 404
    r = client.post("/databases/orders-pg/check", headers=op).json()
    assert r["ok"] is False and r["error"].startswith("OSError")
    events = gate.list_audit(limit=5)
    assert events[0]["event"] == "db_health_check" and events[0]["actor"] == "bob"
    assert client.get("/me", headers=op).json()["features"]["databases"] is True


def test_example_registry_is_valid():
    import json
    from pathlib import Path

    raw = json.loads((Path(__file__).resolve().parents[1] / "examples" / "databases" /
                      "databases.example.json").read_text())
    assert len(validate_registry([DatabaseSpec(**d) for d in raw])) == 6
