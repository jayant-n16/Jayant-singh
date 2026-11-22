"""Executor for ``dr.resync`` proposals: copy drifted tables from the source to the DR copy.

Same-engine pairs only: PostgreSQL, MySQL, CockroachDB and MongoDB. Cross-engine pairs
(PostgreSQL <-> CockroachDB) are refused. Schema differences are never "fixed" here - they are
refused, because changing a DR schema needs a migration, not a data copy.

* CockroachDB: like PostgreSQL (pg wire protocol). Inbound logical data replication jobs on the
  target (``SHOW JOBS``, ``job_type = 'LOGICAL REPLICATION'``, running) are paused with
  ``PAUSE JOB`` and resumed afterwards. Tables larger than ``checksum_max_rows`` are refused
  (one transaction per table; very large tables need a changefeed ``initial_scan`` instead).
* MongoDB: the target must be a writable primary. Each collection is copied into a temporary
  collection with the source's indexes, verified with the same canonical-JSON checksum as the
  consistency check, then swapped in with ``renameCollection`` (``dropTarget``) so readers never
  see a half-copied collection.
* Any engine: Kafka Connect sink connectors listed in the target's ``pause_connectors`` are
  paused first and resumed afterwards (also on failure).

Safety:

* refuses when the DR target is read-only (``default_transaction_read_only`` / ``super_read_only``):
  a locked DR copy must be unlocked through the DR breaker first, never silently here;
* pauses replication into the target while copying (PostgreSQL: disables the target's enabled
  subscriptions; MySQL: ``STOP REPLICA SQL_THREAD``) and resumes it afterwards, also on failure;
* each table is replaced in one transaction (``DELETE`` + chunked ``INSERT``) and then verified with
  the same chunked checksum used by the consistency check; a mismatch is reported as a failure.
"""

from __future__ import annotations

from typing import Any

from oplia_ctl.databases.consistency import (
    ConsistencySettings,
    _q,
    _qualified,
    iter_sql_rows,
    mongo_checksum,
    sql_catalog,
    sql_count,
    table_checksum,
)
from oplia_ctl.databases.registry import DatabaseRegistry, _txt

_ENGINES = ("postgres", "mysql", "cockroachdb", "mongodb")
_TMP_PREFIX = "oplia_resync_"


class ResyncExecutor:
    def __init__(self, registry: DatabaseRegistry, cfg: ConsistencySettings | None = None,
                 kafka_connect: Any = None) -> None:
        self._reg = registry
        self._cfg = cfg or ConsistencySettings()
        self._kc = kafka_connect

    def _specs(self, payload: dict[str, Any]) -> tuple[Any, Any, list[str]]:
        src = self._reg.get(str(payload.get("source", "")))
        dst = self._reg.get(str(payload.get("target", "")))
        if dst.dr_of != src.name:
            raise ValueError(f"{dst.name} is not the DR copy of {src.name}")
        if src.engine != dst.engine or src.engine not in _ENGINES:
            raise ValueError(f"automatic resync needs the same engine on both sides ({', '.join(_ENGINES)}), "
                             f"not {src.engine}->{dst.engine}")
        if dst.pause_connectors and self._kc is None:
            raise ValueError(f"{dst.name} lists pause_connectors but Kafka Connect is not configured")
        if payload.get("schema_issues"):
            raise ValueError("schema differences must be fixed with a migration first: "
                             + ", ".join(map(str, payload["schema_issues"]))[:500])
        tables = [str(t) for t in payload.get("tables") or []]
        if not tables:
            raise ValueError("no tables to resync")
        return src, dst, tables

    def describe(self, payload: dict[str, Any]) -> str:
        src, dst, tables = self._specs(payload)
        what = "collection(s)" if src.engine == "mongodb" else "table(s)"
        extra = f", pausing connectors {', '.join(dst.pause_connectors)}" if dst.pause_connectors else ""
        return (f"Pause replication into {dst.name}{extra}, replace {len(tables)} {what} ({', '.join(tables[:10])}) "
                f"with the data from {src.name}, verify checksums, resume replication")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        src, dst, tables = self._specs(payload)
        paused: list[str] = []
        try:
            for name in dst.pause_connectors:
                self._kc.act(name, "pause")
                paused.append(name)
            sconn, _ = self._reg.connect(src)
            dconn, _ = self._reg.connect(dst)
            try:
                if dst.engine == "postgres":
                    out = self._pg(sconn, dconn, src, dst, tables)
                elif dst.engine == "cockroachdb":
                    out = self._crdb(sconn, dconn, src, dst, tables)
                elif dst.engine == "mongodb":
                    out = self._mongo(sconn, dconn, src, dst, tables)
                else:
                    out = self._mysql(sconn, dconn, src, dst, tables)
            finally:
                sconn.close()
                dconn.close()
        finally:
            for name in paused:
                self._kc.act(name, "resume")
        if paused:
            out["paused_connectors"] = paused
        return out

    def _crdb(self, sconn: Any, dconn: Any, src: Any, dst: Any, tables: list[str]) -> dict[str, Any]:
        ro = str(_txt(dconn.execute("SHOW default_transaction_read_only").fetchone()[0]))
        if ro in ("on", "true"):
            raise RuntimeError(f"{dst.name} is read-only (locked); unlock it through the DR breaker first")
        scat = sql_catalog(sconn, "cockroachdb", src.database)
        for t in tables:
            if t in scat and sql_count(sconn, "cockroachdb", scat[t]) > self._cfg.checksum_max_rows:
                raise ValueError(f"{t}: more than {self._cfg.checksum_max_rows} rows; use a changefeed initial_scan")
        jobs = [int(r[0]) for r in dconn.execute(
            "SELECT job_id FROM [SHOW JOBS] WHERE job_type = 'LOGICAL REPLICATION' AND status = 'running'"
        ).fetchall()]
        for j in jobs:
            dconn.execute(f"PAUSE JOB {int(j)}")
        try:
            def insert(t: Any, cols: list[str], rows: list[tuple[Any, ...]]) -> None:
                collist = ", ".join(_q("cockroachdb", c) for c in cols)
                ph = ", ".join(["%s"] * len(cols))
                with dconn.cursor() as cur:
                    sql = f"INSERT INTO {_qualified('cockroachdb', t)} ({collist}) VALUES ({ph})"  # noqa: S608 # nosec B608
                    cur.executemany(sql, rows)

            results = self._copy_and_verify(
                sconn, dconn, "cockroachdb", src, dst, tables,
                begin=lambda: dconn.execute("BEGIN"), commit=lambda: dconn.execute("COMMIT"),
                rollback=lambda: dconn.execute("ROLLBACK"), insert=insert,
                delete=lambda t: dconn.execute(f"DELETE FROM {_qualified('cockroachdb', t)}"))  # noqa: S608 # nosec B608
        finally:
            for j in jobs:
                dconn.execute(f"RESUME JOB {int(j)}")
        return {"engine": "cockroachdb", "paused_jobs": jobs, "tables": results}

    def _mongo(self, sc: Any, dc: Any, src: Any, dst: Any, colls: list[str]) -> dict[str, Any]:
        if not (src.database and dst.database):
            raise ValueError("MongoDB resync needs 'database' on both sides")
        hello = dc.admin.command("hello")
        if not hello.get("isWritablePrimary", hello.get("ismaster")):
            raise RuntimeError(f"{dst.name} is not a writable primary; resync must run against the DR primary")
        sdb, ddb = sc[src.database], dc[dst.database]
        existing = set(sdb.list_collection_names())
        chunk = self._cfg.checksum_chunk_rows
        results = []
        for name in colls:
            if name not in existing or name.startswith("system."):
                raise ValueError(f"{name}: not a collection on the source")
            tmp = f"{_TMP_PREFIX}{name}"[:120]
            ddb.drop_collection(tmp)
            try:
                batch: list[Any] = []
                copied = 0
                for doc in sdb[name].find({}, batch_size=chunk).sort("_id", 1):
                    batch.append(doc)
                    if len(batch) >= chunk:
                        ddb[tmp].insert_many(batch, ordered=True)
                        copied += len(batch)
                        batch = []
                if batch:
                    ddb[tmp].insert_many(batch, ordered=True)
                    copied += len(batch)
                indexes = 0
                for ix in sdb[name].list_indexes():
                    if ix.get("name") == "_id_":
                        continue
                    opts = {k: v for k, v in ix.items() if k not in ("v", "key", "ns")}
                    ddb[tmp].create_index(list(ix["key"].items()), **opts)
                    indexes += 1
                s_sum, s_n = mongo_checksum(sc, src.database, name, chunk)
                t_sum, t_n = mongo_checksum(dc, dst.database, tmp, chunk)
                if (s_sum, s_n) != (t_sum, t_n):
                    raise RuntimeError(f"{name}: checksum of the copy differs from the source "
                                       f"(source {s_n} docs, copy {t_n}); the source may have changed")
                dc.admin.command("renameCollection", f"{dst.database}.{tmp}", to=f"{dst.database}.{name}",
                                 dropTarget=True)
            except Exception:
                ddb.drop_collection(tmp)
                raise
            results.append({"table": name, "rows_copied": copied, "indexes": indexes, "verified": True,
                            "source_rows": s_n, "target_rows": t_n})
        return {"engine": "mongodb", "tables": results}

    def _copy_and_verify(self, sconn: Any, dconn: Any, engine: str, src: Any, dst: Any, tables: list[str],
                         begin: Any, commit: Any, rollback: Any, insert: Any, delete: Any) -> list[dict[str, Any]]:
        scat = sql_catalog(sconn, engine, src.database)
        dcat = sql_catalog(dconn, engine, dst.database)
        results = []
        for t in tables:
            if t not in scat or t not in dcat or scat[t].columns != dcat[t].columns:
                raise ValueError(f"{t}: schema differs or table missing; not copying")
            if not scat[t].pk:
                raise ValueError(f"{t}: no primary key; refusing to copy without a verifiable key")
            cols = [c[0] for c in scat[t].columns]
            begin()
            try:
                delete(dcat[t])
                batch: list[tuple[Any, ...]] = []
                copied = 0
                for row in iter_sql_rows(sconn, engine, scat[t], self._cfg.checksum_chunk_rows):
                    batch.append(row)
                    if len(batch) >= self._cfg.checksum_chunk_rows:
                        insert(dcat[t], cols, batch)
                        copied += len(batch)
                        batch = []
                if batch:
                    insert(dcat[t], cols, batch)
                    copied += len(batch)
                commit()
            except Exception:
                rollback()
                raise
            s_sum, s_n = table_checksum(iter_sql_rows(sconn, engine, scat[t], self._cfg.checksum_chunk_rows))
            d_sum, d_n = table_checksum(iter_sql_rows(dconn, engine, dcat[t], self._cfg.checksum_chunk_rows))
            results.append({"table": t, "rows_copied": copied, "verified": s_sum == d_sum and s_n == d_n,
                            "source_rows": s_n, "target_rows": d_n})
        bad = [str(r["table"]) for r in results if not r["verified"]]
        if bad:  # the source moved during the copy, or the copy is wrong: never report success
            raise RuntimeError(f"checksum differs after copy for {', '.join(bad)} (source may have changed); "
                               f"results={results}")
        return results

    def _pg(self, sconn: Any, dconn: Any, src: Any, dst: Any, tables: list[str]) -> dict[str, Any]:
        ro = str(_txt(dconn.execute("SHOW default_transaction_read_only").fetchone()[0]))
        if ro in ("on", "true"):
            raise RuntimeError(f"{dst.name} is read-only (locked); unlock it through the DR breaker first")
        subs = [str(_txt(r[0])) for r in dconn.execute(
            "SELECT subname FROM pg_subscription s JOIN pg_database d ON d.oid = s.subdbid "
            "WHERE d.datname = current_database() AND s.subenabled").fetchall()]
        for sub in subs:
            dconn.execute(f"ALTER SUBSCRIPTION {_q('postgres', sub)} DISABLE")
        try:
            def insert(t: Any, cols: list[str], rows: list[tuple[Any, ...]]) -> None:
                collist = ", ".join(_q("postgres", c) for c in cols)
                ph = ", ".join(["%s"] * len(cols))
                with dconn.cursor() as cur:
                    sql = f"INSERT INTO {_qualified('postgres', t)} ({collist}) VALUES ({ph})"  # noqa: S608 # nosec B608
                    cur.executemany(sql, rows)

            results = self._copy_and_verify(
                sconn, dconn, "postgres", src, dst, tables,
                begin=lambda: dconn.execute("BEGIN"), commit=lambda: dconn.execute("COMMIT"),
                rollback=lambda: dconn.execute("ROLLBACK"), insert=insert,
                delete=lambda t: dconn.execute(f"DELETE FROM {_qualified('postgres', t)}"))  # noqa: S608 # nosec B608
        finally:
            for sub in subs:
                dconn.execute(f"ALTER SUBSCRIPTION {_q('postgres', sub)} ENABLE")
        return {"engine": "postgres", "paused_subscriptions": subs, "tables": results}

    def _mysql(self, sconn: Any, dconn: Any, src: Any, dst: Any, tables: list[str]) -> dict[str, Any]:
        with dconn.cursor() as cur:
            cur.execute("SELECT @@GLOBAL.read_only, @@GLOBAL.super_read_only")
            ro, sro = cur.fetchone()
            if int(ro) or int(sro):
                raise RuntimeError(f"{dst.name} is read-only (locked); unlock it through the DR breaker first")
            cur.execute("SHOW REPLICA STATUS")
            replica = bool(cur.fetchone())
            if replica:
                cur.execute("STOP REPLICA SQL_THREAD")
        try:
            def run(sql: str) -> None:
                with dconn.cursor() as cur:
                    cur.execute(sql)

            def insert(t: Any, cols: list[str], rows: list[tuple[Any, ...]]) -> None:
                collist = ", ".join(_q("mysql", c) for c in cols)
                ph = ", ".join(["%s"] * len(cols))
                with dconn.cursor() as cur:
                    sql = f"INSERT INTO {_qualified('mysql', t)} ({collist}) VALUES ({ph})"  # noqa: S608 # nosec B608
                    cur.executemany(sql, rows)

            results = self._copy_and_verify(
                sconn, dconn, "mysql", src, dst, tables,
                begin=lambda: run("START TRANSACTION"), commit=lambda: run("COMMIT"),
                rollback=lambda: run("ROLLBACK"), insert=insert,
                delete=lambda t: run(f"DELETE FROM {_qualified('mysql', t)}"))  # noqa: S608 # nosec B608
        finally:
            if replica:
                with dconn.cursor() as cur:
                    cur.execute("START REPLICA SQL_THREAD")
        return {"engine": "mysql", "paused_replica": replica, "tables": results}
