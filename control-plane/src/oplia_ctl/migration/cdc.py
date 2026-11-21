"""FR-03 change data capture: prerequisite checks, pipeline creation and measured replication lag.

Engines (all created through a gated ``cdc_pipeline`` proposal):

* ``debezium`` - a Debezium source connector (PostgreSQL ``pgoutput``, MySQL binlog, SQL Server,
  Oracle, MongoDB) and the Debezium JDBC sink, created on Kafka Connect with ``PUT
  /connectors/{name}/config``. Credentials are never put in the connector config: it carries Kafka
  Connect config-provider placeholders (``${file:<path>:<key>}``) that resolve on the Connect
  workers from a file mounted from Vault.
* ``aws_dms`` - an AWS DMS ``full-load-and-cdc`` replication task between existing endpoints (create the
  endpoints with ``SecretsManagerSecretId`` so DMS reads the credentials from Secrets Manager).
* ``gcp_datastream`` - a Datastream stream between existing connection profiles. Datastream writes only
  to BigQuery and Cloud Storage; Cloud SQL / Spanner need a Dataflow template after it (documented).
* ``azure_dms`` - an Azure DMS online migration to SQL Managed Instance (log-shipping of backups from a
  blob container; the only online SQL Server path DMS offers - SQL Database is offline only).

Lag (FR-03 asks p99 < 500 ms): ``cdc_lag_probe`` writes heartbeat rows to the source and polls the
target until each one arrives, recording the observed delay per sample and p50/p95/p99. The result
states the SLO verdict from the measurement; nothing is assumed. Managed services do not promise it
either: Datastream documents eventual consistency "within a 1-hour window" and no ordering guarantee.
"""

from __future__ import annotations

import json
import math
import re
import statistics
import time
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from oplia_ctl.replication.jobs import JobMachine

ACTION_CDC_PIPELINE = "migration.cdc_pipeline"
ACTION_CDC_LAG = "migration.cdc_lag_probe"
HEARTBEAT_TABLE = "oplia_cdc_heartbeat"
_NAME = r"^[a-z0-9][a-z0-9-]{0,62}$"
_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}\.[A-Za-z_][A-Za-z0-9_]{0,62}$")


# --------------------------------------------------------------------------- prerequisites
def check_prerequisites(conn: Any, engine: str) -> list[dict[str, Any]]:
    """Read-only checks that CDC can work on this source. Each item: {check, ok, value, fix}."""
    out: list[dict[str, Any]] = []

    def add(check: str, ok: bool, value: Any, fix: str) -> None:
        out.append({"check": check, "ok": bool(ok), "value": value, "fix": "" if ok else fix})

    if engine == "postgres":
        v = conn.execute("SHOW wal_level").fetchone()[0]
        add("wal_level", v == "logical", v, "set wal_level=logical (RDS/Aurora: rds.logical_replication=1; Azure: "
            "wal_level=LOGICAL server parameter; Cloud SQL/AlloyDB: cloudsql.logical_decoding=on) and restart")
        slots = int(conn.execute("SHOW max_replication_slots").fetchone()[0])
        used = int(conn.execute("SELECT count(*) FROM pg_replication_slots").fetchone()[0])
        add("free replication slot", slots - used >= 1, f"{used}/{slots} used", "raise max_replication_slots")
        rep = conn.execute("SELECT rolreplication OR rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()[0]
        add("REPLICATION privilege", rep, bool(rep), "GRANT the REPLICATION attribute (RDS: rds_replication role)")
        return out
    if engine == "mysql":
        with conn.cursor() as cur:
            cur.execute("SELECT @@log_bin, @@binlog_format, @@binlog_row_image, @@gtid_mode")
            log_bin, fmt, image, gtid = cur.fetchone()
        add("binary log enabled", int(log_bin) == 1, log_bin, "enable binary logging (RDS: backup retention > 0)")
        out.append({"check": "binlog retention (advisory)", "ok": True, "value": "not readable generically",
                    "fix": "keep binlogs longer than any connector outage: RDS for MySQL defaults to NULL (not "
                           "retained) - CALL mysql.rds_set_configuration('binlog retention hours', N), max 168; "
                           "Aurora MySQL max 2160"})
        add("binlog_format=ROW", str(fmt).upper() == "ROW", fmt, "set binlog_format=ROW")
        add("binlog_row_image=FULL", str(image).upper() == "FULL", image, "set binlog_row_image=FULL")
        add("gtid_mode=ON (recommended)", str(gtid).upper() == "ON", gtid,
            "gtid_mode=ON lets the connector resume after a failover without re-snapshotting")
        return out
    raise ValueError(f"no CDC prerequisite checks for engine {engine}")


# --------------------------------------------------------------------------- Debezium configs
class DebeziumSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engine: Literal["postgres", "mysql", "sqlserver", "oracle", "mongodb"]
    hostname: str = Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")
    port: int = Field(ge=1, le=65535)
    database: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_$-]{0,62}$")
    tables: list[str] = Field(min_length=1, max_length=500)          # schema.table
    secrets_file: str = Field(pattern=r"^/[A-Za-z0-9._/-]{1,250}\.properties$")
    server_id: int = Field(default=184054, ge=1, le=4294967295)      # MySQL only
    kafka_bootstrap: str = ""                                        # MySQL/SQL Server/Oracle schema history


def debezium_source_config(name: str, s: DebeziumSource) -> dict[str, str]:
    for t in s.tables:
        if not _TABLE.fullmatch(t):
            raise ValueError(f"table {t!r} must be schema.table")
    def secret(k: str) -> str:
        return f"${{file:{s.secrets_file}:{k}}}"

    cfg = {"topic.prefix": name, "database.hostname": s.hostname, "database.port": str(s.port),
           "database.user": secret("username"), "database.password": secret("password"),
           "table.include.list": ",".join(re.escape(t) for t in s.tables), "snapshot.mode": "initial",
           "heartbeat.interval.ms": "10000", "tombstones.on.delete": "false", "decimal.handling.mode": "string",
           "time.precision.mode": "connect"}
    if s.engine == "postgres":
        slot = re.sub(r"[^a-z0-9_]", "_", f"oplia_{name}")
        cfg.update({"connector.class": "io.debezium.connector.postgresql.PostgresConnector", "plugin.name": "pgoutput",
                    "database.dbname": s.database, "slot.name": slot, "publication.name": slot,
                    "publication.autocreate.mode": "filtered"})
    elif s.engine == "mysql":
        cfg.update({"connector.class": "io.debezium.connector.mysql.MySqlConnector",
                    "database.server.id": str(s.server_id), "database.include.list": s.database})
    elif s.engine == "sqlserver":
        cfg.update({"connector.class": "io.debezium.connector.sqlserver.SqlServerConnector",
                    "database.names": s.database, "database.encrypt": "true"})
    elif s.engine == "oracle":
        cfg.update({"connector.class": "io.debezium.connector.oracle.OracleConnector",
                    "database.dbname": s.database, "log.mining.strategy": "online_catalog"})
    else:
        cfg = {"connector.class": "io.debezium.connector.mongodb.MongoDbConnector", "topic.prefix": name,
               "mongodb.connection.string": secret("connection_string"),
               "collection.include.list": ",".join(re.escape(t) for t in s.tables), "snapshot.mode": "initial",
               "heartbeat.interval.ms": "10000"}
    if s.engine in ("mysql", "sqlserver", "oracle"):
        if not s.kafka_bootstrap:
            raise ValueError(f"{s.engine} needs kafka_bootstrap for the schema history topic")
        cfg.update({"schema.history.internal.kafka.bootstrap.servers": s.kafka_bootstrap,
                    "schema.history.internal.kafka.topic": f"{name}.schema-history"})
    return cfg


class JdbcSink(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jdbc_url: str = Field(pattern=r"^jdbc:(postgresql|mysql|sqlserver|oracle:thin|db2):[^\s]{3,500}$")
    secrets_file: str = Field(pattern=r"^/[A-Za-z0-9._/-]{1,250}\.properties$")
    table_name_format: str = Field(default="${source.table}", max_length=200)


def debezium_sink_config(source_name: str, sink: JdbcSink) -> dict[str, str]:
    return {"connector.class": "io.debezium.connector.jdbc.JdbcSinkConnector",
            "connection.url": sink.jdbc_url,
            "connection.username": f"${{file:{sink.secrets_file}:username}}",
            "connection.password": f"${{file:{sink.secrets_file}:password}}",
            "topics.regex": re.escape(source_name) + r"\..+\..+",
            "insert.mode": "upsert", "delete.enabled": "true", "primary.key.mode": "record_key",
            "schema.evolution": "basic", "table.name.format": sink.table_name_format}


# --------------------------------------------------------------------------- pipeline job
class CdcSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kafka_connect: bool = False
    aws_dms_region: str = ""
    gcp_datastream_location: str = ""          # projects/<p>/locations/<l>
    azure_dms: dict[str, str] = Field(default_factory=dict)   # subscription_id, resource_group, managed_instance


class CdcPipeline(JobMachine):
    """PLAN (prerequisites on the source) -> CREATE -> VERIFY -> DONE."""

    kind = "cdc_pipeline"
    action = ACTION_CDC_PIPELINE
    title = "CDC pipeline (FR-03)"
    first_step = "PLAN"

    def __init__(self, cfg: CdcSettings, session_factory: Any, registry: Any = None, kafka_connect: Any = None,
                 secrets: Any = None,
                 dms: Callable[[str], Any] | None = None, datastream: Callable[[], Any] | None = None,
                 azure_dms: Callable[[], Any] | None = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None,
                 sleep: Callable[[float], None] = time.sleep, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg, self.registry, self.kc, self._secrets = cfg, registry, kafka_connect, secrets
        self._dms = dms or (lambda region: __import__("boto3").client("dms", region_name=region))
        self._ds = datastream
        self._az = azure_dms
        self._audit = audit
        self._sleep = sleep

    def engines(self) -> list[str]:
        e = []
        if self.cfg.kafka_connect and self.kc is not None:
            e.append("debezium")
        if self.cfg.aws_dms_region:
            e.append("aws_dms")
        if self.cfg.gcp_datastream_location:
            e.append("gcp_datastream")
        if self.cfg.azure_dms:
            e.append("azure_dms")
        return e

    def fields(self) -> list[dict[str, Any]]:
        return [{"name": "engine", "label": "Engine", "kind": "select", "required": True,
                 "options": [{"value": e, "label": e} for e in self.engines()]},
                {"name": "spec", "label": "Pipeline (JSON)", "kind": "textarea", "required": True,
                 "help": "debezium: {name, source_db, source: {...}, sink: {...}}; aws_dms: {name, "
                         "source_endpoint_arn, target_endpoint_arn, replication_instance_arn, tables}; "
                         "gcp_datastream: {name, source_profile, destination_profile, source_type, dataset}"}]

    def summary(self) -> dict[str, Any]:
        return {"engines": self.engines()}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        engine = str(params.get("engine", ""))
        if engine not in self.engines():
            raise ValueError(f"engine must be one of {self.engines()}")
        spec = params.get("spec", {})
        if isinstance(spec, str):
            spec = json.loads(spec)
        if not isinstance(spec, dict) or not re.fullmatch(_NAME, str(spec.get("name", ""))):
            raise ValueError("spec must be an object with a name (lowercase letters, digits, -)")
        if engine == "debezium":
            DebeziumSource.model_validate(spec["source"])
            if spec.get("sink") is not None:
                JdbcSink.model_validate(spec["sink"])
            if spec.get("source_db") and self.registry is not None:
                self.registry.get(spec["source_db"])
        elif engine == "aws_dms":
            for k in ("source_endpoint_arn", "target_endpoint_arn", "replication_instance_arn"):
                if not re.fullmatch(r"arn:aws[a-z-]*:dms:[a-z0-9-]+:\d{12}:[a-z-]+:[A-Za-z0-9]+", str(spec.get(k))):
                    raise ValueError(f"{k} must be a DMS ARN")
            if not spec.get("tables") or not all(_TABLE.fullmatch(t) for t in spec["tables"]):
                raise ValueError("tables must be schema.table names")
        elif engine == "gcp_datastream":
            for k in ("source_profile", "destination_profile"):
                if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", str(spec.get(k))):
                    raise ValueError(f"{k} must be a connection profile id")
            if spec.get("source_type") not in ("postgresql", "mysql"):
                raise ValueError("source_type must be postgresql or mysql")
            if not re.fullmatch(r"[A-Za-z0-9_]{1,1024}", str(spec.get("dataset", ""))):
                raise ValueError("dataset must be a BigQuery dataset id")
        elif engine == "azure_dms":
            for k in ("source_database", "blob_container_url", "storage_account_key_secret", "source_sql_host"):
                if not spec.get(k):
                    raise ValueError(f"azure_dms needs {k}")
        return {"engine": engine, "spec": spec}

    def target_of(self, payload: dict[str, Any]) -> str:
        return f"{payload['engine']}:{payload['spec']['name']}"

    def describe(self, payload: dict[str, Any]) -> str:
        p = self.parse(payload)
        s = p["spec"]
        if p["engine"] == "debezium":
            return (f"create Debezium connector {s['name']} on {s['source']['engine']} {s['source']['hostname']} "
                    f"({len(s['source']['tables'])} tables)" + (" and a JDBC sink" if s.get("sink") else ""))
        if p["engine"] == "aws_dms":
            return f"create and start AWS DMS task {s['name']} (full load + CDC, {len(s['tables'])} tables)"
        if p["engine"] == "gcp_datastream":
            return f"create and start Datastream stream {s['name']} into BigQuery dataset {s['dataset']}"
        return f"start Azure DMS online migration of {s['source_database']} to SQL Managed Instance"

    # steps
    def _step_plan(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        s = payload["spec"]
        if payload["engine"] == "debezium" and s.get("source_db") and self.registry is not None:
            spec = self.registry.get(s["source_db"])
            conn, _ = self.registry.connect(spec)
            try:
                st["prerequisites"] = check_prerequisites(conn, spec.engine)
            finally:
                conn.close()
            bad = [c for c in st["prerequisites"] if not c["ok"] and "recommended" not in c["check"]]
            if bad:
                raise ValueError("source not ready for CDC: " + "; ".join(f"{c['check']} ({c['fix']})" for c in bad))
        return "CREATE"

    def _step_create(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        s, e = payload["spec"], payload["engine"]
        if e == "debezium":
            src = DebeziumSource.model_validate(s["source"])
            self.kc.put_config(s["name"], debezium_source_config(s["name"], src))
            st["connectors"] = [s["name"]]
            if s.get("sink"):
                self.kc.put_config(f"{s['name']}-sink", debezium_sink_config(s["name"],
                                                                              JdbcSink.model_validate(s["sink"])))
                st["connectors"].append(f"{s['name']}-sink")
        elif e == "aws_dms":
            dms = self._dms(self.cfg.aws_dms_region)
            rules = [{"rule-type": "selection", "rule-id": str(i + 1), "rule-name": f"r{i + 1}",
                      "object-locator": {"schema-name": t.split(".")[0], "table-name": t.split(".")[1]},
                      "rule-action": "include"} for i, t in enumerate(s["tables"])]
            arn = st.get("task_arn")
            if not arn:
                r = dms.create_replication_task(
                    ReplicationTaskIdentifier=s["name"], SourceEndpointArn=s["source_endpoint_arn"],
                    TargetEndpointArn=s["target_endpoint_arn"],
                    ReplicationInstanceArn=s["replication_instance_arn"], MigrationType="full-load-and-cdc",
                    TableMappings=json.dumps({"rules": rules}),
                    ReplicationTaskSettings=json.dumps({"Logging": {"EnableLogging": True},
                                                        "ValidationSettings": {"EnableValidation": True}}))
                st["task_arn"] = arn = r["ReplicationTask"]["ReplicationTaskArn"]
            t = dms.describe_replication_tasks(Filters=[{"Name": "replication-task-arn", "Values": [arn]}])
            status = t["ReplicationTasks"][0]["Status"]
            if status == "creating":
                return "CREATE"                      # DMS needs the task in 'ready' before it can start
            if status == "ready":
                dms.start_replication_task(ReplicationTaskArn=arn, StartReplicationTaskType="start-replication")
        elif e == "gcp_datastream":
            from google.cloud import datastream_v1 as ds
            from google.protobuf import field_mask_pb2

            loc = self.cfg.gcp_datastream_location
            client = self._ds() if self._ds else ds.DatastreamClient()
            src_cfg = ds.SourceConfig(source_connection_profile=f"{loc}/connectionProfiles/{s['source_profile']}")
            if s["source_type"] == "postgresql":
                src_cfg.postgresql_source_config = ds.PostgresqlSourceConfig(
                    publication=s.get("publication", "oplia_pub"), replication_slot=s.get("slot", "oplia_slot"))
            else:
                src_cfg.mysql_source_config = ds.MysqlSourceConfig()
            stream = ds.Stream(display_name=s["name"], source_config=src_cfg,
                               destination_config=ds.DestinationConfig(
                                   destination_connection_profile=f"{loc}/connectionProfiles/{s['destination_profile']}",
                                   bigquery_destination_config=ds.BigQueryDestinationConfig(
                                       single_target_dataset=ds.BigQueryDestinationConfig.SingleTargetDataset(
                                           dataset_id=f"{loc.split('/')[1]}:{s['dataset']}"))),
                               backfill_all=ds.Stream.BackfillAllStrategy())
            if not st.get("stream_created"):
                client.create_stream(parent=loc, stream_id=s["name"], stream=stream).result()
                st["stream_created"] = True
            client.update_stream(stream=ds.Stream(name=f"{loc}/streams/{s['name']}", state=ds.Stream.State.RUNNING),
                                 update_mask=field_mask_pb2.FieldMask(paths=["state"])).result()
        else:
            self._azure_dms(s, st)
        return "VERIFY"

    def _azure_dms(self, s: dict[str, Any], st: dict[str, Any]) -> None:
        from azure.mgmt.datamigration import models as m

        az = self.cfg.azure_dms
        client = self._az() if self._az else None
        if client is None:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.datamigration import DataMigrationManagementClient

            client = DataMigrationManagementClient(DefaultAzureCredential(), az["subscription_id"])
        if self._secrets is None:
            raise RuntimeError("azure_dms needs the secret provider for the storage account key")
        key = self._secrets.get(s["storage_account_key_secret"])
        body = m.DatabaseMigrationSqlMi(properties=m.DatabaseMigrationPropertiesSqlMi(
            scope=(f"/subscriptions/{az['subscription_id']}/resourceGroups/{az['resource_group']}/providers/"
                   f"Microsoft.Sql/managedInstances/{az['managed_instance']}"),
            migration_service=az.get("migration_service"),
            source_database_name=s["source_database"],
            source_sql_connection=m.SqlConnectionInformation(data_source=s["source_sql_host"],
                                                             authentication="SqlAuthentication"),
            backup_configuration=m.BackupConfiguration(source_location=m.SourceLocation(
                azure_blob=m.AzureBlob(account_key=key, blob_container_name=s["blob_container_url"]))),
            offline_configuration=m.OfflineConfiguration(offline=False)))
        client.database_migrations_sql_mi.begin_create_or_update(
            az["resource_group"], az["managed_instance"], s.get("target_database", s["source_database"]), body).result()
        st["azure_migration"] = s.get("target_database", s["source_database"])

    def _step_verify(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        e = payload["engine"]
        if e == "debezium":
            states = {c: self.kc.state(c) for c in st["connectors"]}
            st["status"] = {c: {"connector": v.get("connector", {}).get("state"),
                                "tasks": [t.get("state") for t in v.get("tasks", [])]} for c, v in states.items()}
            if any(v["connector"] == "FAILED" or "FAILED" in v["tasks"] for v in st["status"].values()):
                raise RuntimeError(f"connector failed: {st['status']}")
            if all(v["connector"] == "RUNNING" and v["tasks"] and all(t == "RUNNING" for t in v["tasks"])
                   for v in st["status"].values()):
                return "DONE"
            return "VERIFY"
        if e == "aws_dms":
            t = self._dms(self.cfg.aws_dms_region).describe_replication_tasks(
                Filters=[{"Name": "replication-task-arn", "Values": [st["task_arn"]]}])["ReplicationTasks"][0]
            st["status"] = t["Status"]
            if t["Status"] == "failed":
                raise RuntimeError(f"DMS task failed: {t.get('LastFailureMessage', '')[:500]}")
            return "DONE" if t["Status"] == "running" else "VERIFY"
        if e == "gcp_datastream":
            from google.cloud import datastream_v1 as ds

            client = self._ds() if self._ds else ds.DatastreamClient()
            got = client.get_stream(name=f"{self.cfg.gcp_datastream_location}/streams/{payload['spec']['name']}")
            st["status"] = ds.Stream.State(got.state).name
            if st["status"] in ("FAILED", "FAILED_PERMANENTLY"):
                raise RuntimeError(f"stream {st['status']}: {[e.message for e in got.errors][:3]}")
            return "DONE" if st["status"] == "RUNNING" else "VERIFY"
        return "DONE"

    def finish(self, job: Any) -> None:
        if self._audit is not None:
            self._audit(f"{self.action}.{job.status.lower()}", {"job_id": job.id, "target": job.target,
                                                               "error": job.error})


# --------------------------------------------------------------------------- lag probe
def lag_stats(samples_ms: list[float], slo_ms: float) -> dict[str, Any]:
    if not samples_ms:
        return {"samples": 0, "verdict": "NO DATA"}
    s = sorted(samples_ms)

    def pct(p: float) -> float:
        k = max(0, min(len(s) - 1, math.ceil(p / 100 * len(s)) - 1))   # nearest-rank percentile
        return round(s[k], 1)
    p99 = pct(99)
    return {"samples": len(s), "p50_ms": pct(50), "p95_ms": pct(95), "p99_ms": p99, "max_ms": round(s[-1], 1),
            "mean_ms": round(statistics.fmean(s), 1), "slo_p99_ms": slo_ms,
            "verdict": "MEETS SLO" if p99 < slo_ms else "MISSES SLO",
            "note": "observed by polling the target; poll interval adds up to one interval of error"}


class CdcLagProbe(JobMachine):
    """Writes heartbeat rows on the source and times their arrival on the target (gated: it writes)."""

    kind = "cdc_lag_probe"
    action = ACTION_CDC_LAG
    title = "CDC lag measurement (FR-03)"
    first_step = "PREPARE"

    def __init__(self, registry: Any, session_factory: Any,
                 audit: Callable[[str, dict[str, Any]], None] | None = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.registry, self._audit, self._clock, self._sleep = registry, audit, clock, sleep

    def fields(self) -> list[dict[str, Any]]:
        dbs = [{"value": s.name, "label": f"{s.name} ({s.engine})"} for s in self.registry.specs.values()
               if s.engine in ("postgres", "mysql")]
        return [{"name": "source", "label": "Source", "kind": "select", "required": True, "options": dbs},
                {"name": "target", "label": "Target (replica of the source)", "kind": "select", "required": True,
                 "options": dbs},
                {"name": "samples", "label": "Samples", "kind": "number", "min": 10, "max": 10000, "initial": "200"},
                {"name": "slo_ms", "label": "p99 SLO (ms)", "kind": "number", "min": 1, "max": 3600000,
                 "initial": "500"}]

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        src, dst = self.registry.get(str(params.get("source"))), self.registry.get(str(params.get("target")))
        if src.name == dst.name:
            raise ValueError("source and target must differ")
        for sp in (src, dst):
            if sp.engine not in ("postgres", "mysql"):
                raise ValueError("lag probes run on postgres or mysql")
        n, slo = int(params.get("samples") or 200), float(params.get("slo_ms") or 500)
        if not 10 <= n <= 10000 or not 1 <= slo <= 3600000:
            raise ValueError("samples 10..10000, slo_ms 1..3600000")
        timeout = float(params.get("timeout_s") or 30)
        interval = float(params.get("interval_ms") or 100)
        poll = float(params.get("poll_ms") or 5)
        return {"source": src.name, "target": dst.name, "samples": n, "slo_ms": slo, "timeout_s": timeout,
                "interval_ms": interval, "poll_ms": poll}

    def target_of(self, payload: dict[str, Any]) -> str:
        return f"{payload['source']} -> {payload['target']}"

    def describe(self, payload: dict[str, Any]) -> str:
        p = self.parse(payload)
        return (f"write {p['samples']} heartbeat rows to {HEARTBEAT_TABLE} on {p['source']} and time their arrival "
                f"on {p['target']} (SLO p99 < {p['slo_ms']} ms)")

    def _exec(self, conn: Any, engine: str, sql: str, params: tuple[Any, ...] | None = None) -> list[Any]:
        if engine == "postgres":
            cur = conn.execute(sql, params)
            return list(cur.fetchall()) if cur.description else []
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall()) if cur.description else []

    def _step_prepare(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        spec = self.registry.get(payload["source"])
        conn, _ = self.registry.connect(spec)
        try:
            self._exec(conn, spec.engine, f"CREATE TABLE IF NOT EXISTS {HEARTBEAT_TABLE} (probe VARCHAR(64), "
                                          "seq BIGINT, written_at VARCHAR(40), PRIMARY KEY (probe, seq))")
        finally:
            conn.close()
        st.update(probe=job.id[:8], samples_ms=[], lost=0)
        return "MEASURE"

    def _step_measure(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        s_spec, t_spec = self.registry.get(payload["source"]), self.registry.get(payload["target"])
        sc, _ = self.registry.connect(s_spec)
        tc, _ = self.registry.connect(t_spec)
        ph_s = "%s"
        try:
            for i in range(len(st["samples_ms"]) + st["lost"], payload["samples"]):
                self._exec(sc, s_spec.engine, f"INSERT INTO {HEARTBEAT_TABLE} (probe, seq, written_at) VALUES "  # nosec B608
                                              f"({ph_s}, {ph_s}, {ph_s})", (st["probe"], i, str(time.time())))
                t0 = self._clock()                     # committed (autocommit) when the INSERT returned
                deadline = t0 + payload["timeout_s"]
                seen = False
                while self._clock() < deadline:
                    if self._exec(tc, t_spec.engine, f"SELECT 1 FROM {HEARTBEAT_TABLE} WHERE probe = {ph_s} "  # nosec B608
                                                     f"AND seq = {ph_s}", (st["probe"], i)):
                        st["samples_ms"].append((self._clock() - t0) * 1000)
                        seen = True
                        break
                    self._sleep(payload["poll_ms"] / 1000)
                if not seen:
                    st["lost"] += 1
                self._sleep(payload["interval_ms"] / 1000)
        finally:
            sc.close()
            tc.close()
        st["result"] = {**lag_stats(st["samples_ms"], payload["slo_ms"]), "not_arrived_within_timeout": st["lost"]}
        if st["lost"]:
            st["result"]["verdict"] = "MISSES SLO"
        return "CLEANUP"

    def _step_cleanup(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        spec = self.registry.get(payload["source"])
        conn, _ = self.registry.connect(spec)
        try:
            self._exec(conn, spec.engine, f"DELETE FROM {HEARTBEAT_TABLE} WHERE probe = %s", (st["probe"],))  # nosec B608
        finally:
            conn.close()
        st["samples_ms"] = [round(x, 2) for x in st["samples_ms"]][-2000:]
        return "DONE"

    def finish(self, job: Any) -> None:
        if self._audit is not None:
            r = json.loads(job.state_json).get("result", {})
            self._audit(f"{self.action}.{job.status.lower()}", {"job_id": job.id, "target": job.target,
                                                               "p99_ms": r.get("p99_ms"), "verdict": r.get("verdict")})

