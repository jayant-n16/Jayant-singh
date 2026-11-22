"""DR consistency checks: is each DR copy (``dr_of``) the same as its source?

For every configured pair (target with ``dr_of``), read-only:

1. **Schema** - tables and columns (name, type, nullability) on both sides
   (``information_schema``; MongoDB: collection names and index keys).
2. **Row / document counts** per table / collection.
3. **Checksums** per table (same-engine pairs only: SQL with a primary key), computed in
   chunks with keyset pagination ordered by the primary key - never one huge query. Tables
   without a primary key, or larger than ``checksum_max_rows``, are compared by count only and
   the report says so. MongoDB: per collection, documents ordered by ``_id`` in canonical
   extended JSON.
4. **Replication lag** of the target (from the registry health check).

Because the source keeps changing, a table that differs is checked again once after
``recheck_delay_seconds`` before it counts as drift. If the DR circuit breaker for the stream is
OPEN, differences are expected (replication is held) and the report says so.

Result: CONSISTENT, DRIFT or FAILED, stored (``db_consistency_runs``) and written to the audit log.
Data or schema drift raises a ``dr.resync`` proposal (approve -> execute, see ``ResyncExecutor``).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.databases.models import ConsistencyRunRow
from oplia_ctl.databases.registry import RESYNC_ENGINES, DatabaseRegistry, DatabaseSpec, _scrub, _txt
from oplia_ctl.db import session_scope
from oplia_ctl.safety import ProposalStatus, SafetyGate

ACTION_DR_RESYNC = "dr.resync"
_SAFE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,62}$")


class ConsistencySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_CONSISTENCY_", extra="ignore")
    recheck_delay_seconds: float = Field(default=30.0, ge=0, le=600)
    checksum_chunk_rows: int = Field(default=5000, ge=100, le=100000)
    checksum_max_rows: int = Field(default=5_000_000, ge=0)
    max_tables: int = Field(default=500, ge=1, le=10000)
    max_lag_seconds: float = Field(default=60.0, ge=0)


@dataclass
class TableInfo:
    schema: str                              # actual schema / MySQL database on this side
    table: str
    columns: list[tuple[str, str, str]]      # (name, type, nullable)
    pk: list[str]


def _q(engine: str, ident: str) -> str:
    if not _SAFE.fullmatch(ident):
        raise ValueError(f"unsupported identifier {ident!r}")
    if engine == "mysql":
        return f"`{ident}`"
    if engine == "sqlserver":
        return f"[{ident}]"
    return f'"{ident}"'


# ------------------------------------------------------------------ SQL catalog (PG, CRDB, MySQL, SQL Server, Oracle)
_CURSOR_ENGINES = ("mysql", "sqlserver", "oracle")   # DB-API cursor drivers (psycopg connections execute directly)


def _ph(engine: str, n: int) -> str:
    """The n-th (1-based) bind placeholder of the engine's driver."""
    return f":{n}" if engine == "oracle" else "%s"


def _value(v: Any) -> Any:
    if hasattr(v, "read") and callable(v.read):   # Oracle LOB locators: compare the content, not the locator
        v = v.read()
    return _txt(v)


def _sql_rows(conn: Any, engine: str, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    if engine in _CURSOR_ENGINES:
        cur = conn.cursor()
        try:
            cur.execute(sql, params) if params else cur.execute(sql)
            return [tuple(_value(v) for v in r) for r in cur.fetchall()]
        finally:
            cur.close()
    return [tuple(_txt(v) for v in r) for r in conn.execute(sql, params).fetchall()]


def _oracle_catalog(conn: Any, owner: str | None) -> dict[str, TableInfo]:
    if not owner:
        owner = str(_sql_rows(conn, "oracle", "SELECT USER FROM dual")[0][0])
    owner = owner.upper()
    # tables only (no views), not in the recycle bin, not temporary; bound owner, constant SQL text
    cols = _sql_rows(conn, "oracle",
                     "SELECT c.table_name, c.column_name, c.data_type, c.nullable FROM all_tab_columns c "
                     "JOIN all_tables t ON t.owner = c.owner AND t.table_name = c.table_name "
                     "WHERE c.owner = :1 AND t.dropped = 'NO' AND t.temporary = 'N' "
                     "ORDER BY c.table_name, c.column_id", (owner,))
    pks = _sql_rows(conn, "oracle",
                    "SELECT k.table_name, k.column_name FROM all_constraints c JOIN all_cons_columns k "
                    "ON k.owner = c.owner AND k.constraint_name = c.constraint_name "
                    "WHERE c.owner = :1 AND c.constraint_type = 'P' ORDER BY k.table_name, k.position", (owner,))
    out: dict[str, TableInfo] = {}
    for table, col, dtype, nullable in cols:
        out.setdefault(str(table), TableInfo(owner, str(table), [], [])).columns.append(
            (str(col), str(dtype).lower(), "YES" if str(nullable) == "Y" else "NO"))
    for table, col in pks:
        if str(table) in out and str(col) not in out[str(table)].pk:
            out[str(table)].pk.append(str(col))
    return out


def sql_catalog(conn: Any, engine: str, database: str | None) -> dict[str, TableInfo]:
    """Tables, columns and primary keys. Keys compare the two sides: by table name where the schema
    name may legitimately differ (MySQL database, Oracle owner), by schema.table otherwise."""
    if engine == "oracle":
        return _oracle_catalog(conn, database)
    args: tuple[Any, ...]
    if engine == "sqlserver":
        # the DSN selects the database; system schemas are excluded
        schema_filter = "c.table_schema NOT IN ('sys', 'INFORMATION_SCHEMA', 'guest')"
        args = ()
    elif engine == "mysql":
        schema_filter, args = "c.table_schema = %s", (database,)
        if not database:
            raise ValueError("MySQL consistency checks need 'database' (the schema) on both sides")
    else:
        schema_filter = ("c.table_schema NOT IN ('pg_catalog', 'information_schema', 'crdb_internal', "
                         "'pg_extension') AND c.table_schema NOT LIKE 'pg_toast%%'")
        args = ()
    # the filters are constants above (MySQL schema bound as a parameter): no user input in the SQL text
    cols = _sql_rows(conn, engine,
                     "SELECT c.table_schema, c.table_name, c.column_name, c.data_type, c.is_nullable "  # noqa: S608 # nosec B608
                     "FROM information_schema.columns c JOIN information_schema.tables t "
                     "ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
                     f"WHERE {schema_filter} AND t.table_type = 'BASE TABLE' "
                     "ORDER BY c.table_schema, c.table_name, c.ordinal_position", args)
    pk_filter = schema_filter.replace("c.", "tc.")
    pks = _sql_rows(conn, engine,
                    "SELECT tc.table_schema, tc.table_name, k.column_name "  # noqa: S608 # nosec B608
                    "FROM information_schema.table_constraints tc "
                    "JOIN information_schema.key_column_usage k ON k.constraint_name = tc.constraint_name "
                    "AND k.table_schema = tc.table_schema AND k.table_name = tc.table_name "
                    f"WHERE tc.constraint_type = 'PRIMARY KEY' AND {pk_filter} "
                    "ORDER BY tc.table_schema, tc.table_name, k.ordinal_position", args)
    # Keys compare the two sides: MySQL by table name (the database name may differ between source and
    # DR, it is given per side in the registry), PostgreSQL / CockroachDB by schema.table.
    def key_of(schema: Any, table: Any) -> str:
        return str(table) if engine == "mysql" else f"{schema}.{table}"

    out: dict[str, TableInfo] = {}
    for schema, table, col, dtype, nullable in cols:
        key = key_of(schema, table)
        out.setdefault(key, TableInfo(str(schema), str(table), [], [])).columns.append(
            (str(col), str(dtype).lower(), str(nullable)))
    for schema, table, col in pks:
        key = key_of(schema, table)
        if key in out and str(col) not in out[key].pk:
            out[key].pk.append(str(col))
    return out


def _restrict(info: TableInfo, columns: list[tuple[str, str, str]]) -> TableInfo:
    """The same table limited to ``columns`` (in this side's order); the primary key is kept as is."""
    return TableInfo(info.schema, info.table, [c for c in info.columns if c in columns], list(info.pk))


def _qualified(engine: str, info: TableInfo) -> str:
    return f"{_q(engine, info.schema)}.{_q(engine, info.table)}"


def sql_count(conn: Any, engine: str, info: TableInfo) -> int:
    sql = f"SELECT count(*) FROM {_qualified(engine, info)}"  # noqa: S608 # nosec B608 - identifiers validated by _q
    return int(_sql_rows(conn, engine, sql)[0][0])


def _limit(engine: str, sql_body: str, order: str, n: int) -> str:
    if engine == "sqlserver":
        return f"{sql_body} ORDER BY {order} OFFSET 0 ROWS FETCH NEXT {int(n)} ROWS ONLY"
    if engine == "oracle":
        return f"{sql_body} ORDER BY {order} FETCH FIRST {int(n)} ROWS ONLY"
    return f"{sql_body} ORDER BY {order} LIMIT {int(n)}"


def _after(engine: str, pk: list[str]) -> str:
    """Keyset predicate "row key > last key". Row-value comparison where the engine has it; SQL Server
    and Oracle get the equivalent expanded form (a > ?) OR (a = ? AND b > ?) ..."""
    if engine not in ("sqlserver", "oracle"):
        return f"({', '.join(_q(engine, c) for c in pk)}) > ({', '.join(['%s'] * len(pk))})"
    terms, n = [], 0
    for i in range(len(pk)):
        parts = []
        for j in range(i):
            n += 1
            parts.append(f"{_q(engine, pk[j])} = {_ph(engine, n)}")
        n += 1
        parts.append(f"{_q(engine, pk[i])} > {_ph(engine, n)}")
        terms.append("(" + " AND ".join(parts) + ")")
    return "(" + " OR ".join(terms) + ")"


def _after_params(engine: str, last: tuple[Any, ...]) -> tuple[Any, ...]:
    if engine not in ("sqlserver", "oracle"):
        return last
    out: list[Any] = []
    for i in range(len(last)):
        out.extend(last[: i + 1])
    return tuple(out)


def iter_sql_rows(conn: Any, engine: str, info: TableInfo, chunk: int) -> Iterator[tuple[Any, ...]]:
    """All rows ordered by primary key, fetched ``chunk`` at a time with keyset pagination."""
    cols = ", ".join(_q(engine, c[0]) for c in info.columns)
    pk = ", ".join(_q(engine, c) for c in info.pk)
    pk_idx = [[c[0] for c in info.columns].index(k) for k in info.pk]
    base = f"SELECT {cols} FROM {_qualified(engine, info)}"  # noqa: S608 # nosec B608 - identifiers validated by _q
    last: tuple[Any, ...] | None = None
    while True:
        if last is None:
            rows = _sql_rows(conn, engine, _limit(engine, base, pk, chunk))
        else:
            rows = _sql_rows(conn, engine, _limit(engine, f"{base} WHERE {_after(engine, info.pk)}", pk, chunk),
                             _after_params(engine, last))
        yield from rows
        if len(rows) < chunk:
            return
        last = tuple(rows[-1][i] for i in pk_idx)


def _canon(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()
    return str(v)


def table_checksum(rows: Iterator[tuple[Any, ...]]) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    for r in rows:
        h.update(json.dumps([_canon(v) for v in r], separators=(",", ":")).encode())
        h.update(b"\n")
        n += 1
    return h.hexdigest(), n


# ------------------------------------------------------------------ MongoDB
def mongo_catalog(client: Any, database: str) -> dict[str, list[str]]:
    db = client[database]
    out = {}
    for name in sorted(db.list_collection_names()):
        if name.startswith("system."):
            continue
        out[name] = sorted(json.dumps(ix.get("key"), sort_keys=True, default=str) for ix in db[name].list_indexes())
    return out


def mongo_checksum(client: Any, database: str, coll: str, chunk: int) -> tuple[str, int]:
    from bson import json_util

    h = hashlib.sha256()
    n = 0
    for doc in client[database][coll].find({}, batch_size=chunk).sort("_id", 1):
        h.update(json_util.dumps(doc, json_options=json_util.CANONICAL_JSON_OPTIONS, sort_keys=True).encode())
        h.update(b"\n")
        n += 1
    return h.hexdigest(), n


# ------------------------------------------------------------------ checker
class ConsistencyChecker:
    def __init__(self, registry: DatabaseRegistry, gate: SafetyGate, sf: sessionmaker[Session],
                 cfg: ConsistencySettings | None = None,
                 breaker_state: Callable[[], dict[str, Any] | None] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._reg = registry
        self._gate = gate
        self._sf = sf
        self._cfg = cfg or ConsistencySettings()
        self._breaker = breaker_state
        self._sleep = sleep
        self._clock = clock

    def pairs(self) -> list[tuple[DatabaseSpec, DatabaseSpec]]:
        return [(self._reg.specs[s.dr_of], s) for s in self._reg.specs.values() if s.dr_of]

    # -- one comparison pass -------------------------------------------------------------
    def _compare_sql(self, src: DatabaseSpec, dst: DatabaseSpec, only: set[str] | None) -> dict[str, Any]:
        cfg = self._cfg
        sconn, _ = self._reg.connect(src)
        try:
            dconn, _ = self._reg.connect(dst)
        except Exception:
            sconn.close()
            raise
        try:
            scat = sql_catalog(sconn, src.engine, src.database)
            dcat = sql_catalog(dconn, dst.engine, dst.database)
            same_engine = src.engine == dst.engine
            schema: list[dict[str, Any]] = []
            tables: dict[str, dict[str, Any]] = {}
            names = sorted(set(scat) | set(dcat))
            if len(names) > cfg.max_tables:
                raise ValueError(f"{len(names)} tables exceed max_tables={cfg.max_tables}")
            for t in names:
                if only is not None and t not in only:
                    continue
                if t not in dcat:
                    schema.append({"table": t, "issue": "missing on DR target"})
                    continue
                if t not in scat:
                    schema.append({"table": t, "issue": "only on DR target"})
                    continue
                s_info, d_info = scat[t], dcat[t]
                compared_on: list[str] | None = None
                if same_engine and s_info.columns != d_info.columns:
                    schema.append({"table": t, "issue": "columns differ",
                                   "source": s_info.columns, "target": d_info.columns})
                    # Data is still compared over the columns both sides have with the same name, type
                    # and nullability, so a schema difference never hides a data difference.
                    common = [c for c in s_info.columns if c in d_info.columns]
                    s_info, d_info = _restrict(s_info, common), _restrict(d_info, common)
                    compared_on = [c[0] for c in common]
                if not same_engine and [c[0] for c in s_info.columns] != [c[0] for c in d_info.columns]:
                    schema.append({"table": t, "issue": "column names differ"})
                sc, dc = sql_count(sconn, src.engine, s_info), sql_count(dconn, dst.engine, d_info)
                entry: dict[str, Any] = {"source_rows": sc, "target_rows": dc, "match": sc == dc}
                if compared_on is not None:
                    entry["compared_columns"] = compared_on
                if compared_on is not None and (not compared_on or not set(s_info.pk) <= set(compared_on)
                                                or not s_info.pk or s_info.pk != d_info.pk):
                    entry["checksum"] = "skipped: primary key differs or is not in the common columns (counts only)"
                elif not same_engine:
                    entry["checksum"] = "skipped: different engines (counts only)"
                elif not s_info.pk:
                    entry["checksum"] = "skipped: no primary key (counts only)"
                elif max(sc, dc) > cfg.checksum_max_rows:
                    entry["checksum"] = f"skipped: more than {cfg.checksum_max_rows} rows (counts only)"
                elif sc == dc:
                    s_sum, _ = table_checksum(iter_sql_rows(sconn, src.engine, s_info, cfg.checksum_chunk_rows))
                    d_sum, _ = table_checksum(iter_sql_rows(dconn, dst.engine, d_info, cfg.checksum_chunk_rows))
                    entry["checksum"] = "match" if s_sum == d_sum else "differ"
                    entry["match"] = s_sum == d_sum
                tables[t] = entry
            return {"schema": schema, "tables": tables}
        finally:
            sconn.close()
            dconn.close()

    def _compare_mongo(self, src: DatabaseSpec, dst: DatabaseSpec, only: set[str] | None) -> dict[str, Any]:
        if not (src.database and dst.database):
            raise ValueError("MongoDB consistency checks need 'database' on both sides")
        sc, _ = self._reg.connect(src)
        dc, _ = self._reg.connect(dst)
        try:
            scat, dcat = mongo_catalog(sc, src.database), mongo_catalog(dc, dst.database)
            schema: list[dict[str, Any]] = []
            tables: dict[str, dict[str, Any]] = {}
            for name in sorted(set(scat) | set(dcat)):
                if only is not None and name not in only:
                    continue
                if name not in dcat or name not in scat:
                    schema.append({"table": name, "issue": "missing on DR target" if name not in dcat
                                   else "only on DR target"})
                    continue
                if scat[name] != dcat[name]:
                    schema.append({"table": name, "issue": "indexes differ"})
                s_n = sc[src.database][name].count_documents({})
                d_n = dc[dst.database][name].count_documents({})
                entry: dict[str, Any] = {"source_rows": s_n, "target_rows": d_n, "match": s_n == d_n}
                if s_n == d_n and s_n <= self._cfg.checksum_max_rows:
                    s_sum, _ = mongo_checksum(sc, src.database, name, self._cfg.checksum_chunk_rows)
                    d_sum, _ = mongo_checksum(dc, dst.database, name, self._cfg.checksum_chunk_rows)
                    entry["checksum"] = "match" if s_sum == d_sum else "differ"
                    entry["match"] = s_sum == d_sum
                elif s_n == d_n:
                    entry["checksum"] = f"skipped: more than {self._cfg.checksum_max_rows} documents"
                tables[name] = entry
            return {"schema": schema, "tables": tables}
        finally:
            sc.close()
            dc.close()

    def _compare(self, src: DatabaseSpec, dst: DatabaseSpec, only: set[str] | None = None) -> dict[str, Any]:
        if src.engine == "mongodb":
            return self._compare_mongo(src, dst, only)
        return self._compare_sql(src, dst, only)

    # -- full run ------------------------------------------------------------------------
    def run(self, pair: str, *, triggered_by: str) -> dict[str, Any]:
        dst = self._reg.get(pair)
        if not dst.dr_of:
            raise LookupError(f"{pair} is not a DR copy (no dr_of)")
        src = self._reg.get(dst.dr_of)
        run_id = str(uuid.uuid4())
        started = self._clock()
        report: dict[str, Any] = {"source": src.name, "target": dst.name}
        status = "CONSISTENT"
        summary = ""
        proposal_id: str | None = None
        try:
            first = self._compare(src, dst)
            differing = {t for t, e in first["tables"].items() if not e["match"]}
            if differing and self._cfg.recheck_delay_seconds >= 0:
                self._sleep(self._cfg.recheck_delay_seconds)
                again = self._compare(src, dst, only=differing)
                for t in differing:
                    if t in again["tables"]:
                        first["tables"][t] = {**again["tables"][t], "rechecked": True}
            report.update(first)
            health = self._reg.check(dst.name, triggered_by=f"consistency:{triggered_by}")
            report["target_health"] = {"ok": health["ok"], "error": health["error"],
                                       "replication": health["detail"].get("replication")}
            lag = _max_lag(health["detail"].get("replication"))
            if src.engine == "sqlserver" and lag is None:
                # Always On: secondary_lag_seconds is documented from the primary's side
                lag = self._sqlserver_lag_from_primary(src)
            report["lag_seconds"] = lag
            breaker = self._breaker() if self._breaker else None
            if breaker:
                report["dr_breaker"] = breaker
            drift_tables = sorted(t for t, e in report["tables"].items() if not e["match"])
            findings = len(report["schema"]) + len(drift_tables)
            lag_exceeded = lag is not None and lag > self._cfg.max_lag_seconds
            if findings or lag_exceeded:
                status = "DRIFT"
                parts = []
                if report["schema"]:
                    parts.append(f"{len(report['schema'])} schema difference(s)")
                if drift_tables:
                    parts.append(f"{len(drift_tables)} table(s) with different data: {', '.join(drift_tables[:10])}")
                if lag_exceeded:
                    parts.append(f"replication lag {lag:.1f}s > {self._cfg.max_lag_seconds:.0f}s")
                summary = "; ".join(parts)
                if breaker and breaker.get("state") == "OPEN":
                    summary += " (DR breaker is OPEN: replication is held, differences are expected)"
            else:
                summary = f"{len(report['tables'])} table(s) identical"
            resync_supported = src.engine == dst.engine and src.engine in RESYNC_ENGINES
            report["resync_supported"] = resync_supported
            if findings and not resync_supported:
                summary += (f" (no automatic resync for {src.engine}: repair through the native replication, "
                            "e.g. reseed the availability group or re-instantiate the standby)")
            if findings and resync_supported and not (breaker and breaker.get("state") == "OPEN"):
                payload = {"source": src.name, "target": dst.name,
                           "tables": drift_tables, "schema_issues": [s["table"] for s in report["schema"]]}
                prefix = f"dr-resync:{src.name}->{dst.name}:"
                open_one = self._gate.latest_by_idempotency_prefix(prefix)
                if (open_one is not None and open_one[0].status in (ProposalStatus.PENDING, ProposalStatus.APPROVED)
                        and open_one[0].payload == payload):
                    # the same drift is already waiting for a decision: link this run to it, never a duplicate
                    proposal_id = open_one[0].id
                    report["resync_proposal_reused"] = True
                else:
                    p = self._gate.propose(
                        action_type=ACTION_DR_RESYNC, target=f"{src.name}->{dst.name}", payload=payload,
                        reason=f"DR consistency check found drift between {src.name} and {dst.name}: {summary}"[:2000],
                        requested_by="consistency-checker", idempotency_key=f"{prefix}{run_id}")
                    proposal_id = p.id
        except Exception as exc:
            status = "FAILED"
            summary = _scrub(f"{type(exc).__name__}: {exc}", "")
            report["error"] = summary
        finished = self._clock()
        with session_scope(self._sf) as s:
            s.add(ConsistencyRunRow(id=run_id, pair=dst.name, started_at=started, finished_at=finished,
                                    status=status, summary=summary[:4000],
                                    report_json=json.dumps(report, default=str), triggered_by=triggered_by,
                                    proposal_id=proposal_id))
        self._gate.record_event(actor=triggered_by, event="dr_consistency_check", proposal_id=proposal_id,
                                detail={"pair": dst.name, "status": status, "summary": summary[:500]})
        return {"id": run_id, "pair": dst.name, "status": status, "summary": summary, "report": report,
                "proposal_id": proposal_id, "started_at": started.isoformat(), "finished_at": finished.isoformat()}

    def _sqlserver_lag_from_primary(self, src: DatabaseSpec) -> float | None:
        """Largest secondary_lag_seconds of this database's secondaries, read on the primary (SQL Server
        2016+; needs VIEW SERVER PERFORMANCE STATE on 2022+, VIEW SERVER STATE before). None if the
        database is in no availability group or the permission is missing."""
        conn, _ = self._reg.connect(src)
        try:
            rows = _sql_rows(conn, "sqlserver",
                             "SELECT MAX(secondary_lag_seconds) FROM sys.dm_hadr_database_replica_states "
                             "WHERE database_id = DB_ID() AND is_local = 0")
            v = rows[0][0] if rows else None
            return None if v is None else float(v)
        except Exception:
            return None
        finally:
            conn.close()

    def list_runs(self, pair: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        q = select(ConsistencyRunRow).order_by(ConsistencyRunRow.started_at.desc()).limit(max(1, min(limit, 500)))
        if pair:
            q = q.where(ConsistencyRunRow.pair == pair)
        with session_scope(self._sf) as s:
            return [{"id": r.id, "pair": r.pair, "status": r.status, "summary": r.summary,
                     "report": json.loads(r.report_json), "triggered_by": r.triggered_by,
                     "proposal_id": r.proposal_id, "started_at": _iso(r.started_at),
                     "finished_at": _iso(r.finished_at)} for r in s.execute(q).scalars()]


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


def _max_lag(rep: Any) -> float | None:
    if not isinstance(rep, dict):
        return None
    vals: list[float] = []
    for k in ("lag_seconds", "replay_lag_seconds"):
        if isinstance(rep.get(k), (int, float)):
            vals.append(float(rep[k]))
    for f in rep.get("changefeeds") or []:
        if isinstance(f.get("lag_seconds"), (int, float)):
            vals.append(float(f["lag_seconds"]))
    return max(vals) if vals else None
