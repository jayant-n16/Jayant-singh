"""FR-03 CDC: Debezium configs, Kafka Connect calls, AWS DMS (botocore Stubber against the real DMS model),
Datastream and Azure DMS (their official SDK model classes, fake transport), prerequisite checks and a
measured lag probe over real PostgreSQL logical replication (OPLIA_TEST_PG_LOGICAL_URL: a server with
wal_level=logical). No cloud account is used."""

from __future__ import annotations

import json
import os

import boto3
import httpx
import pytest
import respx
from botocore.stub import ANY, Stubber

from oplia_ctl.databases.registry import DatabaseRegistry, DatabaseSpec
from oplia_ctl.http import ResilientClient
from oplia_ctl.migration.cdc import (
    CdcLagProbe,
    CdcPipeline,
    CdcSettings,
    DebeziumSource,
    JdbcSink,
    check_prerequisites,
    debezium_sink_config,
    debezium_source_config,
    lag_stats,
)
from oplia_ctl.replication.pipelines import KafkaConnect
from oplia_ctl.secrets import StaticSecretProvider

PG_URL = os.environ.get("OPLIA_TEST_DATABASE_URL", "").replace("postgresql+psycopg://", "postgresql://")
PG_LOGICAL = os.environ.get("OPLIA_TEST_PG_LOGICAL_URL", "")
MYSQL_PORT = os.environ.get("OPLIA_TEST_MYSQL_PORT", "")
ARN = "arn:aws:dms:eu-west-1:123456789012:{}:ABCDEF123"


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


SRC = {"engine": "postgres", "hostname": "orders-db.example.internal", "port": 5432, "database": "shop",
       "tables": ["public.orders", "public.order_lines"], "secrets_file": "/opt/kafka/secrets/shop.properties"}
SINK = {"jdbc_url": "jdbc:postgresql://alloydb.example.internal:5432/shop",
        "secrets_file": "/opt/kafka/secrets/alloydb.properties"}


def test_debezium_configs_never_contain_credentials():
    src = debezium_source_config("shop-cdc", DebeziumSource.model_validate(SRC))
    assert src["connector.class"] == "io.debezium.connector.postgresql.PostgresConnector"
    assert src["plugin.name"] == "pgoutput" and src["publication.autocreate.mode"] == "filtered"
    assert src["database.password"] == "${file:/opt/kafka/secrets/shop.properties:password}"
    assert src["table.include.list"] == r"public\.orders,public\.order_lines"
    sink = debezium_sink_config("shop-cdc", JdbcSink.model_validate(SINK))
    assert sink["connector.class"] == "io.debezium.connector.jdbc.JdbcSinkConnector"
    assert sink["primary.key.mode"] == "record_key" and sink["delete.enabled"] == "true"
    assert sink["insert.mode"] == "upsert" and sink["topics.regex"] == r"shop\-cdc\..+\..+"
    my = debezium_source_config("m", DebeziumSource.model_validate({**SRC, "engine": "mysql",
                                                                     "kafka_bootstrap": "kafka:9092"}))
    assert my["schema.history.internal.kafka.topic"] == "m.schema-history"
    with pytest.raises(ValueError, match="kafka_bootstrap"):
        debezium_source_config("m", DebeziumSource.model_validate({**SRC, "engine": "oracle"}))
    with pytest.raises(ValueError, match=r"schema\.table"):
        debezium_source_config("m", DebeziumSource.model_validate({**SRC, "tables": ["orders"]}))
    with pytest.raises(ValueError):
        JdbcSink.model_validate({**SINK, "jdbc_url": "jdbc:postgresql://x/y; DROP"})


@respx.mock
def test_debezium_pipeline_creates_connectors_and_waits_for_running(session_factory):
    kc_url = "http://connect:8083"
    put = respx.put(url__regex=rf"{kc_url}/connectors/[^/]+/config").mock(return_value=httpx.Response(201, json={}))
    states = iter([{"connector": {"state": "RUNNING"}, "tasks": [{"state": "UNASSIGNED"}]},
                   {"connector": {"state": "RUNNING"}, "tasks": []},
                   {"connector": {"state": "RUNNING"}, "tasks": [{"state": "RUNNING"}]},
                   {"connector": {"state": "RUNNING"}, "tasks": [{"state": "RUNNING"}]}])
    respx.get(url__regex=rf"{kc_url}/connectors/[^/]+/status").mock(
        side_effect=lambda r: httpx.Response(200, json=next(states)))
    kc = KafkaConnect(kc_url, ResilientClient(timeout=5, max_retries=0))
    events = []
    m = CdcPipeline(CdcSettings(kafka_connect=True), session_factory, kafka_connect=kc,
                    audit=lambda e, d: events.append(e))
    jid = m(m.parse({"engine": "debezium", "spec": json.dumps({"name": "shop-cdc", "source": SRC,
                                                                 "sink": SINK})}))["job_id"]
    for _ in range(5):
        m.run_pending()
    j = m.get(jid)
    assert j["status"] == "SUCCEEDED", j
    assert [c.request.url.path for c in put.calls] == ["/connectors/shop-cdc/config",
                                                        "/connectors/shop-cdc-sink/config"]
    sent = json.loads(put.calls[0].request.content)
    assert sent["database.password"].startswith("${file:") and sent["database.user"].startswith("${file:")
    assert events == ["migration.cdc_pipeline.succeeded"]
    with pytest.raises(ValueError, match="engine must be one of"):
        m.parse({"engine": "aws_dms", "spec": {"name": "x"}})


def test_aws_dms_task_against_the_real_dms_model(session_factory):
    dms = boto3.client("dms", region_name="eu-west-1")
    stub = Stubber(dms)
    task_arn = ARN.format("task")
    stub.add_response("create_replication_task", {"ReplicationTask": {"ReplicationTaskArn": task_arn,
                                                                      "Status": "creating"}},
                      {"ReplicationTaskIdentifier": "shop-dms", "SourceEndpointArn": ARN.format("endpoint"),
                       "TargetEndpointArn": ARN.format("endpoint"), "ReplicationInstanceArn": ARN.format("rep"),
                       "MigrationType": "full-load-and-cdc", "TableMappings": ANY, "ReplicationTaskSettings": ANY})
    flt = {"Filters": [{"Name": "replication-task-arn", "Values": [task_arn]}]}
    stub.add_response("describe_replication_tasks", {"ReplicationTasks": [{"Status": "creating"}]}, flt)
    stub.add_response("describe_replication_tasks", {"ReplicationTasks": [{"Status": "ready"}]}, flt)
    stub.add_response("start_replication_task", {"ReplicationTask": {"Status": "starting"}},
                      {"ReplicationTaskArn": task_arn, "StartReplicationTaskType": "start-replication"})
    stub.add_response("describe_replication_tasks", {"ReplicationTasks": [{"Status": "running"}]}, flt)
    stub.activate()
    m = CdcPipeline(CdcSettings(aws_dms_region="eu-west-1"), session_factory, dms=lambda region: dms)
    spec = {"name": "shop-dms", "source_endpoint_arn": ARN.format("endpoint"),
            "target_endpoint_arn": ARN.format("endpoint"), "replication_instance_arn": ARN.format("rep"),
            "tables": ["public.orders"]}
    jid = m(m.parse({"engine": "aws_dms", "spec": spec}))["job_id"]
    for _ in range(4):
        m.run_pending()
    assert m.get(jid)["status"] == "SUCCEEDED", m.get(jid)
    stub.assert_no_pending_responses()
    with pytest.raises(ValueError, match="DMS ARN"):
        m.parse({"engine": "aws_dms", "spec": {**spec, "source_endpoint_arn": "nope"}})


class FakeOp:
    def result(self):
        return None


class FakeDatastream:
    def __init__(self):
        self.created, self.updated, self.states = [], [], ["STARTING", "RUNNING"]

    def create_stream(self, parent, stream_id, stream):
        self.created.append((parent, stream_id, stream))
        return FakeOp()

    def update_stream(self, stream, update_mask):
        self.updated.append((stream, list(update_mask.paths)))
        return FakeOp()

    def get_stream(self, name):
        from google.cloud import datastream_v1 as ds

        return ds.Stream(name=name, state=ds.Stream.State[self.states.pop(0)])


def test_datastream_stream_uses_the_sdk_models(session_factory):
    from google.cloud import datastream_v1 as ds

    fake = FakeDatastream()
    loc = "projects/oplia-mig/locations/europe-west4"
    m = CdcPipeline(CdcSettings(gcp_datastream_location=loc), session_factory, datastream=lambda: fake)
    jid = m(m.parse({"engine": "gcp_datastream", "spec": {"name": "shop-ds", "source_profile": "pg-src",
                                                          "destination_profile": "bq-dst",
                                                          "source_type": "postgresql",
                                                          "dataset": "shop_raw"}}))["job_id"]
    for _ in range(4):
        m.run_pending()
    assert m.get(jid)["status"] == "SUCCEEDED", m.get(jid)
    parent, sid, stream = fake.created[0]
    assert (parent, sid) == (loc, "shop-ds") and isinstance(stream, ds.Stream)
    assert stream.source_config.postgresql_source_config.publication == "oplia_pub"
    assert stream.destination_config.bigquery_destination_config.single_target_dataset.dataset_id == \
        "oplia-mig:shop_raw"
    assert fake.updated[0][1] == ["state"] and fake.updated[0][0].state == ds.Stream.State.RUNNING


def test_azure_dms_sql_mi_uses_the_sdk_models(session_factory):
    calls = []

    class Ops:
        def begin_create_or_update(self, rg, mi, db, body):
            calls.append((rg, mi, db, body))
            return FakeOp()

    class Client:
        database_migrations_sql_mi = Ops()

    m = CdcPipeline(CdcSettings(azure_dms={"subscription_id": "00000000-0000-0000-0000-000000000001",
                                           "resource_group": "mig", "managed_instance": "sqlmi1",
                                           "migration_service": "/subscriptions/x/sqlMigrationServices/dms1"}),
                    session_factory, azure_dms=lambda: Client(),
                    secrets=StaticSecretProvider({"blob_key": "k3y"}))
    jid = m(m.parse({"engine": "azure_dms", "spec": {"name": "orders-mi", "source_database": "Orders",
                                                     "source_sql_host": "sql01.corp", "blob_container_url": "backups",
                                                     "storage_account_key_secret": "blob_key"}}))["job_id"]
    m.run_pending()
    assert m.get(jid)["status"] == "SUCCEEDED", m.get(jid)
    rg, mi, db, body = calls[0]
    ser = body.serialize()
    assert (rg, mi, db) == ("mig", "sqlmi1", "Orders")
    assert ser["properties"]["kind"] == "SqlMi" and ser["properties"]["offlineConfiguration"]["offline"] is False
    assert ser["properties"]["scope"].endswith("/Microsoft.Sql/managedInstances/sqlmi1")
    assert "k3y" not in json.dumps(m.get(jid))            # the key never lands in job state


def test_lag_stats():
    r = lag_stats([float(x) for x in range(1, 101)], 50)
    assert (r["p50_ms"], r["p99_ms"], r["max_ms"], r["verdict"]) == (50.0, 99.0, 100.0, "MISSES SLO")
    assert lag_stats([1.0] * 10, 500)["verdict"] == "MEETS SLO" and lag_stats([], 1)["verdict"] == "NO DATA"


@pytest.mark.skipif(not PG_URL, reason="needs PostgreSQL (OPLIA_TEST_DATABASE_URL)")
def test_postgres_prerequisites_are_read_from_the_server():
    import psycopg

    with psycopg.connect(PG_URL, autocommit=True) as c:
        checks = {x["check"]: x for x in check_prerequisites(c, "postgres")}
        wal = c.execute("SHOW wal_level").fetchone()[0]
    assert checks["wal_level"]["ok"] is (wal == "logical") and checks["wal_level"]["value"] == wal
    assert checks["REPLICATION privilege"]["ok"] is True       # tests connect as a superuser


@pytest.mark.skipif(not MYSQL_PORT, reason="needs MySQL (scripts/test-mysql.sh)")
def test_mysql_prerequisites_are_read_from_the_server():
    import pymysql

    c = pymysql.connect(host="127.0.0.1", port=int(MYSQL_PORT), user="oplia_cc",
                        password=os.environ["OPLIA_TEST_MYSQL_PW"], autocommit=True)
    checks = {x["check"]: x for x in check_prerequisites(c, "mysql")}
    assert checks["binary log enabled"]["ok"] and checks["binlog_format=ROW"]["ok"]


@pytest.mark.skipif(not PG_LOGICAL, reason="needs PostgreSQL with wal_level=logical (OPLIA_TEST_PG_LOGICAL_URL)")
def test_lag_probe_over_real_logical_replication(session_factory):
    import psycopg

    base = PG_LOGICAL.rsplit("/", 1)[0]
    with psycopg.connect(PG_LOGICAL, autocommit=True) as c:
        for db in ("lag_src", "lag_dst"):
            c.execute(f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")
        c.execute("SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'oplia_lag'")
        c.execute("CREATE DATABASE lag_src")
        c.execute("CREATE DATABASE lag_dst")
    ddl = ("CREATE TABLE oplia_cdc_heartbeat (probe VARCHAR(64), seq BIGINT, written_at VARCHAR(40), "
           "PRIMARY KEY (probe, seq))")
    with psycopg.connect(f"{base}/lag_src", autocommit=True) as s, psycopg.connect(f"{base}/lag_dst",
                                                                                  autocommit=True) as d:
        s.execute(ddl)
        d.execute(ddl)
        s.execute("CREATE PUBLICATION oplia_lag FOR TABLE oplia_cdc_heartbeat")
        s.execute("SELECT pg_create_logical_replication_slot('oplia_lag', 'pgoutput')")
        # the subscription connects from the server itself: use its own port on loopback (in CI the server runs
        # in a container whose published port differs from the one it listens on)
        port = d.execute("SELECT current_setting('port')").fetchone()[0]
        user, _, pw = base.replace("postgresql://", "").rpartition("@")[0].partition(":")
        d.execute(f"CREATE SUBSCRIPTION oplia_lag CONNECTION 'host=127.0.0.1 port={port} user={user} "
                  f"{('password=' + pw) if pw else ''} dbname=lag_src' PUBLICATION oplia_lag "
                  "WITH (create_slot = false, slot_name = 'oplia_lag')")
        try:
            reg = DatabaseRegistry([DatabaseSpec(name="src", engine="postgres", cloud="aws", role="primary",
                                                 dsn_secret="s"),
                                    DatabaseSpec(name="dst", engine="postgres", cloud="gcp", role="replica",
                                                 dr_of="src", dsn_secret="d")],
                                   StaticSecretProvider({"s": f"{base}/lag_src", "d": f"{base}/lag_dst"}),
                                   session_factory)
            m = CdcLagProbe(reg, session_factory)
            jid = m(m.parse({"source": "src", "target": "dst", "samples": 40, "slo_ms": 500, "interval_ms": 20,
                             "timeout_s": 20}))["job_id"]
            for _ in range(5):
                m.run_pending()
            j = m.get(jid)
            assert j["status"] == "SUCCEEDED", j
            r = j["state"]["result"]
            print("measured logical-replication lag:", r)
            assert r["samples"] == 40 and r["not_arrived_within_timeout"] == 0
            assert r["verdict"] in ("MEETS SLO", "MISSES SLO") and r["p50_ms"] <= r["p99_ms"] <= r["max_ms"]
        finally:
            d.execute("DROP SUBSCRIPTION oplia_lag")
