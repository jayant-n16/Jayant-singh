"""dr.resync for MongoDB and CockroachDB.

Integration tests run against real servers when OPLIA_TEST_MONGO_URL / OPLIA_TEST_CRDB_URL are set
(CI starts mongo and cockroach containers); the unit tests use small fakes for the error paths.
"""

from __future__ import annotations

import os

import pytest

from oplia_ctl.databases.consistency import ConsistencyChecker, ConsistencySettings
from oplia_ctl.databases.registry import DatabaseRegistry, DatabaseSpec
from oplia_ctl.databases.resync import ResyncExecutor
from oplia_ctl.safety import ProposalStatus
from oplia_ctl.secrets import StaticSecretProvider

MONGO_URL = os.environ.get("OPLIA_TEST_MONGO_URL", "")
CRDB_URL = os.environ.get("OPLIA_TEST_CRDB_URL", "")
CFG = ConsistencySettings(recheck_delay_seconds=0, checksum_chunk_rows=100)


def _specs(engine, src_db, dst_db, **dr):
    return [DatabaseSpec(name="src", engine=engine, cloud="aws", role="primary", dsn_secret="s", database=src_db),
            DatabaseSpec(name="dr", engine=engine, cloud="gcp", role="dr", dr_of="src", dsn_secret="d",
                         database=dst_db, **dr)]


class FakeKC:
    def __init__(self):
        self.calls = []

    def act(self, name, action):
        self.calls.append((name, action))


# ----------------------------------------------------------------------------- unit
def test_cross_engine_and_missing_kafka_connect_are_refused(session_factory):
    specs = [DatabaseSpec(name="src", engine="postgres", cloud="aws", role="primary", dsn_secret="s"),
             DatabaseSpec(name="dr", engine="cockroachdb", cloud="gcp", role="dr", dr_of="src", dsn_secret="d")]
    reg = DatabaseRegistry(specs, StaticSecretProvider({}), session_factory)
    with pytest.raises(ValueError, match="same engine"):
        ResyncExecutor(reg, CFG).describe({"source": "src", "target": "dr", "tables": ["public.t"]})
    reg = DatabaseRegistry(_specs("mongodb", "a", "b", pause_connectors=["mongo-sink"]),
                           StaticSecretProvider({}), session_factory)
    with pytest.raises(ValueError, match="Kafka Connect is not configured"):
        ResyncExecutor(reg, CFG).describe({"source": "src", "target": "dr", "tables": ["c"]})
    assert "pausing connectors mongo-sink" in ResyncExecutor(reg, CFG, kafka_connect=FakeKC()).describe(
        {"source": "src", "target": "dr", "tables": ["c"]})


class _Admin:
    def __init__(self, writable):
        self.writable = writable

    def command(self, name, *a, **kw):
        assert name == "hello"
        return {"isWritablePrimary": self.writable}


class _Client:
    def __init__(self, writable=True):
        self.admin = _Admin(writable)

    def close(self):
        pass


def test_mongo_secondary_is_refused_and_connectors_resumed(session_factory):
    kc = FakeKC()
    reg = DatabaseRegistry(_specs("mongodb", "a", "b", pause_connectors=["mongo-sink"]),
                           StaticSecretProvider({"s": "mongodb://s", "d": "mongodb://d"}), session_factory,
                           connectors={"mongodb": lambda uri: _Client(writable=not uri.endswith("d"))})
    with pytest.raises(RuntimeError, match="not a writable primary"):
        ResyncExecutor(reg, CFG, kafka_connect=kc)({"source": "src", "target": "dr", "tables": ["c"]})
    assert kc.calls == [("mongo-sink", "pause"), ("mongo-sink", "resume")]


# ----------------------------------------------------------------------------- MongoDB (real)
@pytest.fixture
def mongo_pair():
    if not MONGO_URL:
        pytest.skip("needs MongoDB (OPLIA_TEST_MONGO_URL)")
    from pymongo import ASCENDING, MongoClient

    c = MongoClient(MONGO_URL, directConnection=True)
    for db in ("rs_src", "rs_dr"):
        c.drop_database(db)
        docs = [{"_id": i, "user": f"u{i}", "n": i, "tags": ["a", "b"], "nested": {"x": i / 3}} for i in range(1, 251)]
        c[db]["sessions"].insert_many(docs)
        c[db]["sessions"].create_index([("user", ASCENDING)], unique=True, name="user_1")
        c[db]["events"].insert_many([{"_id": i, "k": "e"} for i in range(30)])
    yield c, {"s": MONGO_URL, "d": MONGO_URL}
    c.close()


def test_mongo_drift_resync_restores_documents_and_indexes(gate, session_factory, mongo_pair):
    c, secrets = mongo_pair
    reg = DatabaseRegistry(_specs("mongodb", "rs_src", "rs_dr"), StaticSecretProvider(secrets), session_factory)
    checker = ConsistencyChecker(reg, gate, session_factory, cfg=CFG)
    assert checker.run("dr", triggered_by="alice")["status"] == "CONSISTENT"

    c["rs_dr"]["sessions"].update_one({"_id": 7}, {"$set": {"n": -1}})        # same count, other data
    c["rs_dr"]["sessions"].delete_one({"_id": 8})
    c["rs_dr"]["sessions"].insert_one({"_id": 999, "user": "ghost", "n": 0})
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "DRIFT" and r["report"]["tables"]["sessions"]["checksum"] == "differ"
    p = gate.get(r["proposal_id"])
    assert p.payload["tables"] == ["sessions"]

    gate.approve(p.id, "bob")
    done = gate.execute(p.id, ResyncExecutor(reg, CFG), "ops")
    assert done.status is ProposalStatus.EXECUTED, done.result
    assert done.result["tables"] == [{"table": "sessions", "rows_copied": 250, "indexes": 1, "verified": True,
                                      "source_rows": 250, "target_rows": 250}]
    assert checker.run("dr", triggered_by="alice")["status"] == "CONSISTENT"
    names = c["rs_dr"].list_collection_names()
    assert not any(n.startswith("oplia_resync_") for n in names)
    ix = {i["name"]: i for i in c["rs_dr"]["sessions"].list_indexes()}
    assert ix["user_1"].get("unique") is True


def test_mongo_failed_copy_leaves_target_untouched(gate, session_factory, mongo_pair):
    c, secrets = mongo_pair
    reg = DatabaseRegistry(_specs("mongodb", "rs_src", "rs_dr"), StaticSecretProvider(secrets), session_factory)
    c["rs_dr"]["events"].delete_one({"_id": 0})
    with pytest.raises(ValueError, match="not a collection on the source"):
        ResyncExecutor(reg, CFG)({"source": "src", "target": "dr", "tables": ["events", "nope"]})
    # "events" was swapped in before "nope" failed; the failing one left no temporary collection
    assert c["rs_dr"]["events"].count_documents({}) == 30
    assert not any(n.startswith("oplia_resync_") for n in c["rs_dr"].list_collection_names())


# ----------------------------------------------------------------------------- CockroachDB (real)
@pytest.fixture
def crdb_pair():
    if not CRDB_URL:
        pytest.skip("needs CockroachDB (OPLIA_TEST_CRDB_URL)")
    import psycopg

    base = CRDB_URL.rsplit("/", 1)[0]
    with psycopg.connect(CRDB_URL, autocommit=True) as c:
        for db in ("cr_src", "cr_dr"):
            c.execute(f"DROP DATABASE IF EXISTS {db} CASCADE")
            c.execute(f"CREATE DATABASE {db}")
    conns = {db: psycopg.connect(f"{base}/{db}", autocommit=True) for db in ("cr_src", "cr_dr")}
    for cn in conns.values():
        cn.execute("CREATE TABLE orders (id INT8 PRIMARY KEY, amount DECIMAL(12,2), note STRING, at TIMESTAMPTZ)")
        cn.execute("INSERT INTO orders SELECT g, g * 1.5, 'n' || g::STRING, "
                   "'2026-01-01'::TIMESTAMPTZ + g * INTERVAL '1 minute' FROM generate_series(1, 250) g")
    yield conns, {"s": f"{base}/cr_src", "d": f"{base}/cr_dr"}
    for cn in conns.values():
        cn.close()


def test_crdb_drift_and_resync(gate, session_factory, crdb_pair):
    conns, secrets = crdb_pair
    reg = DatabaseRegistry(_specs("cockroachdb", "cr_src", "cr_dr"), StaticSecretProvider(secrets), session_factory)
    checker = ConsistencyChecker(reg, gate, session_factory, cfg=CFG)
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "CONSISTENT", r
    conns["cr_dr"].execute("UPDATE orders SET amount = amount + 0.01 WHERE id = 42")
    r = checker.run("dr", triggered_by="alice")
    assert r["status"] == "DRIFT", r
    table = r["report"]["tables"]
    assert table["public.orders"]["checksum"] == "differ"
    gate.approve(r["proposal_id"], "bob")
    done = gate.execute(r["proposal_id"], ResyncExecutor(reg, CFG), "ops")
    assert done.status is ProposalStatus.EXECUTED, done.result
    assert done.result["engine"] == "cockroachdb" and done.result["paused_jobs"] == []
    assert done.result["tables"][0]["verified"] is True
    assert checker.run("dr", triggered_by="alice")["status"] == "CONSISTENT"


def test_crdb_refuses_read_only_target_and_oversized_tables(gate, session_factory, crdb_pair):
    conns, secrets = crdb_pair
    reg = DatabaseRegistry(_specs("cockroachdb", "cr_src", "cr_dr"), StaticSecretProvider(secrets), session_factory)
    small = ConsistencySettings(recheck_delay_seconds=0, checksum_chunk_rows=100, checksum_max_rows=100)
    with pytest.raises(ValueError, match="more than 100 rows"):
        ResyncExecutor(reg, small)({"source": "src", "target": "dr", "tables": ["public.orders"]})
    # role defaults: observed in CI that ALTER DATABASE ... SET did not apply to the root user, so the
    # DR copy is reached as a normal SQL user whose session default is read-only
    c = conns["cr_dr"]
    c.execute("DROP USER IF EXISTS oplia_dr")
    c.execute("CREATE USER oplia_dr")
    c.execute("GRANT ALL ON DATABASE cr_dr TO oplia_dr")
    c.execute("GRANT ALL ON TABLE cr_dr.public.* TO oplia_dr")
    c.execute("ALTER ROLE oplia_dr IN DATABASE cr_dr SET default_transaction_read_only = on")
    base = secrets["d"].rsplit("/", 1)[0].replace("root@", "oplia_dr@")
    ro = {**secrets, "d": f"{base}/cr_dr"}
    reg = DatabaseRegistry(_specs("cockroachdb", "cr_src", "cr_dr"), StaticSecretProvider(ro), session_factory)
    with pytest.raises(RuntimeError, match="read-only"):
        ResyncExecutor(reg, CFG)({"source": "src", "target": "dr", "tables": ["public.orders"]})
    assert c.execute("SELECT count(*) FROM orders").fetchone()[0] == 250
