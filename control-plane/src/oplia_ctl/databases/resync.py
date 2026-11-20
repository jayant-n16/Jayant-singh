"""Executor for ``dr.resync`` proposals: copy drifted tables from the source to the DR copy.

Only same-engine PostgreSQL -> PostgreSQL and MySQL -> MySQL are supported; anything else is
refused with the reason (MongoDB: re-run initial sync of the member; CockroachDB: restart the
changefeed with ``initial_scan``). Schema differences are never "fixed" here - they are refused,
because changing a DR schema needs a migration, not a data copy.

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
    sql_catalog,
    table_checksum,
)
from oplia_ctl.databases.registry import DatabaseRegistry, _txt


class ResyncExecutor:
    def __init__(self, registry: DatabaseRegistry, cfg: ConsistencySettings | None = None) -> None:
        self._reg = registry
        self._cfg = cfg or ConsistencySettings()

    def _specs(self, payload: dict[str, Any]) -> tuple[Any, Any, list[str]]:
        src = self._reg.get(str(payload.get("source", "")))
        dst = self._reg.get(str(payload.get("target", "")))
        if dst.dr_of != src.name:
            raise ValueError(f"{dst.name} is not the DR copy of {src.name}")
        if src.engine != dst.engine or src.engine not in ("postgres", "mysql"):
            raise ValueError(f"automatic resync supports postgres->postgres and mysql->mysql only, "
                             f"not {src.engine}->{dst.engine}")
        if payload.get("schema_issues"):
            raise ValueError("schema differences must be fixed with a migration first: "
                             + ", ".join(map(str, payload["schema_issues"]))[:500])
        tables = [str(t) for t in payload.get("tables") or []]
        if not tables:
            raise ValueError("no tables to resync")
        return src, dst, tables

    def describe(self, payload: dict[str, Any]) -> str:
        src, dst, tables = self._specs(payload)
        return (f"Pause replication into {dst.name}, replace {len(tables)} table(s) ({', '.join(tables[:10])}) "
                f"with the rows from {src.name}, verify checksums, resume replication")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        src, dst, tables = self._specs(payload)
        sconn, _ = self._reg.connect(src)
        dconn, _ = self._reg.connect(dst)
        try:
            if dst.engine == "postgres":
                return self._pg(sconn, dconn, src, dst, tables)
            return self._mysql(sconn, dconn, src, dst, tables)
        finally:
            sconn.close()
            dconn.close()

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
