"""Database registry and read-only health checks.

Databases are declared in configuration (``OPLIA_DATABASES``, JSON list); credentials are a
*secret name* (resolved from Vault / the secret provider at call time) and never leave this module:
results and errors are scrubbed of the DSN and its password.

Health check per engine (read-only statements only):

* PostgreSQL - ``version()``, ``pg_is_in_recovery()``, ``default_transaction_read_only``; on a
  standby the replay lag ``now() - pg_last_xact_replay_timestamp()``; on a primary the streaming
  replicas (``pg_stat_replication``) with their replay lag, and enabled logical subscriptions.
* MySQL 8 - ``VERSION()``, ``@@read_only`` / ``@@super_read_only``, ``SHOW REPLICA STATUS``
  (IO/SQL thread state, ``Seconds_Behind_Source``).
* MongoDB - ``buildInfo``, ``hello`` (primary / secondary, replica-set name) and, when allowed,
  ``replSetGetStatus`` to compute this member's lag behind the primary.
* CockroachDB - ``version()``, ``default_transaction_read_only`` and changefeed jobs with their
  high-water mark (lag = now - high-water).
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.databases.models import DbHealthCheckRow
from oplia_ctl.db import session_scope
from oplia_ctl.secrets import SecretProvider
from oplia_ctl.timeutil import iso_utc

Engine = Literal["postgres", "mysql", "mongodb", "cockroachdb", "sqlserver", "oracle"]
# engines the DR consistency check and resync support (a dr_of pair must use one of these)
DR_ENGINES = ("postgres", "mysql", "mongodb", "cockroachdb")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$-]{0,62}$")


class DatabaseSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    engine: Engine
    cloud: Literal["aws", "azure", "gcp", "ibm", "onprem"]
    role: Literal["primary", "dr", "replica"]
    dsn_secret: str = Field(min_length=1, max_length=128)
    database: str | None = None          # postgres / cockroachdb / mysql schema / mongodb database
    dr_of: str | None = None             # for role=dr|replica: the name of its source database
    description: str = Field(default="", max_length=200)
    # Kafka Connect sink connectors that write INTO this DR copy; paused while a resync replaces data
    pause_connectors: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def _check(self) -> DatabaseSpec:
        if self.database is not None and not _IDENT.fullmatch(self.database):
            raise ValueError(f"{self.name}: invalid database name")
        if self.role == "primary" and self.dr_of:
            raise ValueError(f"{self.name}: a primary cannot have dr_of")
        if self.dr_of and self.engine not in DR_ENGINES:
            raise ValueError(f"{self.name}: DR consistency checks support {', '.join(DR_ENGINES)}, not {self.engine}; "
                             "leave dr_of unset for this database")
        return self

    def public(self) -> dict[str, Any]:
        return self.model_dump(exclude={"dsn_secret"})


def validate_registry(specs: list[DatabaseSpec]) -> dict[str, DatabaseSpec]:
    by_name: dict[str, DatabaseSpec] = {}
    for s in specs:
        if s.name in by_name:
            raise ValueError(f"database names must be unique: {s.name}")
        by_name[s.name] = s
    for s in specs:
        if s.dr_of is not None:
            src = by_name.get(s.dr_of)
            if src is None:
                raise ValueError(f"{s.name}: dr_of={s.dr_of!r} is not a configured database")
            if src.engine != s.engine and {src.engine, s.engine} != {"postgres", "cockroachdb"}:
                raise ValueError(f"{s.name}: engine {s.engine} cannot be a copy of {src.engine}")
    return by_name


def _scrub(message: str, secret: str) -> str:
    out = message
    if secret:
        out = out.replace(secret, "<dsn>")
        try:
            pw = urlsplit(secret).password
        except ValueError:
            pw = None
        if pw:
            out = out.replace(pw, "<password>").replace(unquote(pw), "<password>")
    out = re.sub(r"password=\S+", "password=<password>", out)
    return out[:500]


def _now() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- connectors
def connect_postgres(dsn: str) -> Any:
    import psycopg

    return psycopg.connect(dsn, autocommit=True, connect_timeout=10)


def connect_mysql(dsn: str) -> Any:
    import pymysql

    u = urlsplit(dsn)
    if u.scheme != "mysql" or not u.hostname:
        raise ValueError("MySQL DSN must be mysql://user:password@host:port/[db]")
    q = parse_qs(u.query)
    ssl = {"ca": q["ssl_ca"][0]} if "ssl_ca" in q else None
    return pymysql.connect(host=u.hostname, port=u.port or 3306, user=unquote(u.username or ""),
                           password=unquote(u.password or ""), database=(u.path.lstrip("/") or None),
                           connect_timeout=10, read_timeout=60, autocommit=True, ssl=ssl)


def connect_mongo(uri: str) -> Any:
    from pymongo import MongoClient

    return MongoClient(uri, serverSelectionTimeoutMS=10000, directConnection=True)


def connect_sqlserver(dsn: str) -> Any:
    """``sqlserver://user:password@host:port/database`` via pymssql (FreeTDS is bundled in the wheel).

    Query options: ``tds_version`` (default 7.4) and ``encrypt`` (FreeTDS ``encryption``: off/request/require)."""
    import pymssql

    u = urlsplit(dsn)
    if u.scheme != "sqlserver" or not u.hostname:
        raise ValueError("SQL Server DSN must be sqlserver://user:password@host:port/database")
    q = parse_qs(u.query)
    kw: dict[str, Any] = {}
    if "encrypt" in q:
        kw["encryption"] = q["encrypt"][0]
    return pymssql.connect(server=u.hostname, port=str(u.port or 1433), user=unquote(u.username or ""),
                           password=unquote(u.password or ""), database=(u.path.lstrip("/") or "master"),
                           login_timeout=10, timeout=120, autocommit=True,
                           tds_version=q.get("tds_version", ["7.4"])[0], **kw)


def connect_oracle(dsn: str) -> Any:
    """``oracle://user:password@host:port/service_name`` via python-oracledb thin mode (no client libraries)."""
    import oracledb

    u = urlsplit(dsn)
    if u.scheme != "oracle" or not u.hostname or not u.path.lstrip("/"):
        raise ValueError("Oracle DSN must be oracle://user:password@host:port/service_name")
    conn = oracledb.connect(user=unquote(u.username or ""), password=unquote(u.password or ""),
                            dsn=f"{u.hostname}:{u.port or 1521}/{u.path.lstrip('/')}", tcp_connect_timeout=10)
    conn.autocommit = True
    return conn


Connectors = dict[str, Callable[[str], Any]]
DEFAULT_CONNECTORS: Connectors = {"postgres": connect_postgres, "cockroachdb": connect_postgres,
                                  "mysql": connect_mysql, "mongodb": connect_mongo,
                                  "sqlserver": connect_sqlserver, "oracle": connect_oracle}


def _txt(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode("utf-8", "replace")
    if isinstance(v, Decimal):
        return float(v)
    return v


# --------------------------------------------------------------------------- health
def _pg_health(c: Any, engine: str) -> dict[str, Any]:
    def one(sql: str) -> Any:
        return _txt(c.execute(sql).fetchone()[0])

    out: dict[str, Any] = {"version": str(one("SELECT version()"))[:200],
                           "read_only": str(one("SHOW default_transaction_read_only")) in ("on", "true")}
    if engine == "cockroachdb":
        feeds = []
        for job_id, status, hw in c.execute(
                "SELECT job_id, status, high_water_timestamp FROM [SHOW CHANGEFEED JOBS]").fetchall():
            lag = None
            if hw is not None:
                lag = round(time.time() - float(Decimal(str(_txt(hw)))) / 1e9, 3)
            feeds.append({"job_id": str(job_id), "status": str(_txt(status)), "lag_seconds": lag})
        out["role"] = "cluster"
        out["replication"] = {"changefeeds": feeds}
        return out
    standby = bool(one("SELECT pg_is_in_recovery()"))
    out["role"] = "standby" if standby else "primary"
    if standby:
        lag = one("SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))")
        out["replication"] = {"replay_lag_seconds": None if lag is None else round(float(lag), 3)}
    else:
        replicas = [{"application": str(_txt(a)), "state": str(_txt(s)),
                     "replay_lag_seconds": None if lag is None else round(float(lag), 3)}
                    for a, s, lag in c.execute(
                        "SELECT application_name, state, EXTRACT(EPOCH FROM replay_lag) "
                        "FROM pg_stat_replication").fetchall()]
        subs = [str(_txt(r[0])) for r in c.execute(
            "SELECT subname FROM pg_subscription s JOIN pg_database d ON d.oid = s.subdbid "
            "WHERE d.datname = current_database() AND s.subenabled").fetchall()]
        out["replication"] = {"streaming_replicas": replicas, "enabled_subscriptions": subs}
    return out


def _mysql_health(conn: Any) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute("SELECT VERSION(), @@GLOBAL.read_only, @@GLOBAL.super_read_only")
        version, ro, sro = cur.fetchone()
        cur.execute("SHOW REPLICA STATUS")
        row = cur.fetchone()
        cols = [d[0] for d in cur.description or []]
    out: dict[str, Any] = {"version": str(version), "read_only": bool(int(ro)) or bool(int(sro))}
    if row:
        st = dict(zip(cols, row, strict=False))
        behind = st.get("Seconds_Behind_Source")
        out["role"] = "replica"
        out["replication"] = {"io_running": str(st.get("Replica_IO_Running")),
                              "sql_running": str(st.get("Replica_SQL_Running")),
                              "lag_seconds": None if behind is None else float(behind),
                              "last_error": str(st.get("Last_Error") or "")[:300]}
    else:
        out["role"] = "primary"
        out["replication"] = {}
    return out


def _mssql_health(conn: Any) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute("SELECT @@VERSION, CAST(SERVERPROPERTY('Edition') AS nvarchar(128)), "
                    "CAST(DATABASEPROPERTYEX(DB_NAME(), 'Updateability') AS nvarchar(32))")
        version, edition, upd = cur.fetchone()
        out: dict[str, Any] = {"version": str(version).splitlines()[0][:200], "edition": str(edition),
                               "read_only": str(upd) == "READ_ONLY", "role": "primary", "replication": {}}
        try:   # Always On availability groups: role of the local replica, when the database is in one
            cur.execute("SELECT rs.role_desc, drs.synchronization_state_desc, drs.secondary_lag_seconds "
                        "FROM sys.dm_hadr_database_replica_states drs JOIN sys.dm_hadr_availability_replica_states "
                        "rs ON rs.replica_id = drs.replica_id WHERE drs.database_id = DB_ID() AND drs.is_local = 1")
            row = cur.fetchone()
            if row:
                out["role"] = str(row[0]).lower()
                out["replication"] = {"availability_group": True, "state": str(row[1]),
                                      "lag_seconds": None if row[2] is None else float(row[2])}
        except Exception as exc:   # needs VIEW SERVER STATE; report, do not fail the health check
            out["replication"] = {"status_error": type(exc).__name__}
    return out


def _oracle_health(conn: Any) -> dict[str, Any]:
    with conn.cursor() as cur:
        try:
            cur.execute("SELECT banner FROM v$version")
            version = str(cur.fetchone()[0])[:200]
        except Exception:   # v$version not granted: PRODUCT_COMPONENT_VERSION is readable by every user
            cur.execute("SELECT product || ' ' || version FROM product_component_version")
            version = str(cur.fetchone()[0])[:200]
        out: dict[str, Any] = {"version": version, "role": "unknown", "read_only": None, "replication": {}}
        try:   # v$database needs SELECT_CATALOG_ROLE (or SELECT on v_$database); report, do not fail
            cur.execute("SELECT database_role, open_mode FROM v$database")
            role, mode = cur.fetchone()
            out["role"] = str(role).lower()
            out["read_only"] = "READ ONLY" in str(mode)
        except Exception as exc:
            out["replication"] = {"status_error": type(exc).__name__}
    return out


def _mongo_health(client: Any) -> dict[str, Any]:
    admin = client.admin
    version = str(admin.command("buildInfo").get("version"))
    hello = admin.command("hello")
    out: dict[str, Any] = {"version": version, "read_only": not bool(hello.get("isWritablePrimary")),
                           "role": "primary" if hello.get("isWritablePrimary") else
                           ("secondary" if hello.get("secondary") else "standalone-or-other")}
    rep: dict[str, Any] = {"set_name": hello.get("setName")}
    if hello.get("setName"):
        try:
            status = admin.command("replSetGetStatus")
            members = status.get("members", [])
            primary = next((m for m in members if m.get("stateStr") == "PRIMARY"), None)
            me = next((m for m in members if m.get("self")), None)
            if primary and me and primary.get("optimeDate") and me.get("optimeDate"):
                rep["lag_seconds"] = (primary["optimeDate"] - me["optimeDate"]).total_seconds()
        except Exception as exc:  # replSetGetStatus needs clusterMonitor; report, do not fail
            rep["status_error"] = type(exc).__name__
    out["replication"] = rep
    return out


class DatabaseRegistry:
    def __init__(self, specs: list[DatabaseSpec], secrets: SecretProvider, sf: sessionmaker[Session],
                 connectors: Connectors | None = None, clock: Callable[[], datetime] = _now) -> None:
        self.specs = validate_registry(specs)
        self._secrets = secrets
        self._sf = sf
        self._connectors = {**DEFAULT_CONNECTORS, **(connectors or {})}
        self._clock = clock

    def get(self, name: str) -> DatabaseSpec:
        try:
            return self.specs[name]
        except KeyError:
            raise LookupError(name) from None

    def dsn(self, spec: DatabaseSpec) -> str:
        return self._secrets.get(spec.dsn_secret)

    def connect(self, spec: DatabaseSpec) -> tuple[Any, str]:
        dsn = self.dsn(spec)
        return self._connectors[spec.engine](dsn), dsn

    def check(self, name: str, *, triggered_by: str) -> dict[str, Any]:
        spec = self.get(name)
        started = time.monotonic()
        detail: dict[str, Any] = {}
        error: str | None = None
        dsn = ""
        try:
            dsn = self.dsn(spec)  # resolved first, so it can be scrubbed from any connection error
            conn = self._connectors[spec.engine](dsn)
            try:
                if spec.engine in ("postgres", "cockroachdb"):
                    detail = _pg_health(conn, spec.engine)
                elif spec.engine == "mysql":
                    detail = _mysql_health(conn)
                elif spec.engine == "sqlserver":
                    detail = _mssql_health(conn)
                elif spec.engine == "oracle":
                    detail = _oracle_health(conn)
                else:
                    detail = _mongo_health(conn)
            finally:
                conn.close()
        except Exception as exc:
            error = _scrub(f"{type(exc).__name__}: {exc}", dsn)
        latency = round((time.monotonic() - started) * 1000, 1)
        row = DbHealthCheckRow(id=str(uuid.uuid4()), database=name, checked_at=self._clock(), ok=error is None,
                               latency_ms=latency, detail_json=json.dumps(detail, default=str), error=error,
                               triggered_by=triggered_by)
        with session_scope(self._sf) as s:
            s.add(row)
        return {"database": name, "checked_at": iso_utc(row.checked_at), "ok": error is None,
                "latency_ms": latency, "detail": detail, "error": error, "triggered_by": triggered_by}

    def check_all(self, *, triggered_by: str) -> list[dict[str, Any]]:
        return [self.check(n, triggered_by=triggered_by) for n in self.specs]

    def latest(self) -> list[dict[str, Any]]:
        out = []
        with session_scope(self._sf) as s:
            for name, spec in self.specs.items():
                row = s.execute(select(DbHealthCheckRow).where(DbHealthCheckRow.database == name)
                                .order_by(DbHealthCheckRow.checked_at.desc()).limit(1)).scalar_one_or_none()
                last = None
                if row is not None:
                    at = row.checked_at if row.checked_at.tzinfo else row.checked_at.replace(tzinfo=UTC)
                    last = {"checked_at": at.astimezone(UTC).isoformat(), "ok": row.ok,
                            "latency_ms": row.latency_ms, "detail": json.loads(row.detail_json),
                            "error": row.error, "triggered_by": row.triggered_by}
                out.append({**spec.public(), "last_check": last})
        return out
