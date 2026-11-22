"""FR-05 parity checks between a source and its migrated copy (gated read-only job; run it on a schedule
through the job worker for continuous verification).

* ``exact`` (SQL -> SQL, any engines): every row is hashed after type normalisation (booleans, decimals,
  timestamps in UTC, bytes, UUIDs) and the hashes are summed per bucket of the primary key. The sum does not
  depend on row order, so different collations on the two sides cannot cause false differences. Buckets that
  differ are re-read to list the exact primary keys that are missing, extra or changed.
* ``documents`` (SQL -> MongoDB API / DynamoDB): each source row is compared with the target document of the
  same key on the shared columns.
* ``shape`` (document stores): field-name and value-type histograms of a sample, source vs target.
* ``vector``: cosine similarity between stored embeddings and freshly computed ones for a sample; the
  threshold is part of the result.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime, time
from decimal import Decimal
from typing import Any

from oplia_ctl.databases.consistency import TableInfo, iter_sql_rows, sql_catalog
from oplia_ctl.replication.jobs import JobMachine

ACTION_PARITY = "migration.parity_check"
MOD = 2 ** 256


def norm(v: Any) -> Any:
    """One canonical form per value across PostgreSQL, MySQL and document stores."""
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return repr(float(v))
    if isinstance(v, Decimal):
        return format(v.normalize(), "f")
    if isinstance(v, datetime):
        if v.tzinfo is not None:
            v = v.astimezone(UTC).replace(tzinfo=None)
        return v.isoformat()
    if isinstance(v, (date, time)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, default=str)
    s = str(v)
    try:                                      # numeric strings (Debezium decimal.handling.mode=string)
        d = Decimal(s)
        if d.is_finite() and s.strip() == s and any(ch.isdigit() for ch in s):
            return format(d.normalize(), "f")
    except Exception:  # noqa: S110 # nosec B110 - not a number: compared as text
        pass
    return s


def row_hash(values: list[Any]) -> int:
    return int.from_bytes(hashlib.sha256(json.dumps([norm(v) for v in values]).encode()).digest(), "big")


def bucket(pk: list[Any], buckets: int) -> int:
    return int.from_bytes(hashlib.sha256(json.dumps([norm(v) for v in pk]).encode()).digest()[:8], "big") % buckets


def _scan(conn: Any, engine: str, info: TableInfo, cols: list[str], chunk: int) -> Iterator[tuple[list[Any], int]]:
    idx = [[c[0] for c in info.columns].index(c) for c in cols]
    pk_idx = [[c[0] for c in info.columns].index(k) for k in info.pk]
    for r in iter_sql_rows(conn, engine, info, chunk):
        yield [r[i] for i in pk_idx], row_hash([r[i] for i in idx])


def _by_name(cat: dict[str, TableInfo]) -> dict[str, TableInfo]:
    """Key tables by bare name so PostgreSQL ``schema.table`` and MySQL ``table`` line up; a name that exists in
    several PostgreSQL schemas keeps its qualified key."""
    names = Counter(i.table for i in cat.values())
    return {(i.table if names[i.table] == 1 else k): i for k, i in cat.items()}


def compare_exact(src: tuple[Any, str, str | None], dst: tuple[Any, str, str | None], tables: list[str] | None,
                  buckets: int = 64, chunk: int = 5000, max_keys: int = 50) -> dict[str, Any]:
    (sc, se, sdb), (dc, de, ddb) = src, dst
    scat, dcat = _by_name(sql_catalog(sc, se, sdb)), _by_name(sql_catalog(dc, de, ddb))
    out: dict[str, Any] = {"tables": {}, "schema": []}
    for t in sorted(tables or scat):
        if t not in scat or t not in dcat:
            out["schema"].append({"table": t, "issue": "missing on target" if t in scat else "missing on source"})
            continue
        s_info, d_info = scat[t], dcat[t]
        if not s_info.pk:
            out["tables"][t] = {"status": "SKIPPED", "why": "no primary key on the source"}
            continue
        cols = [c[0] for c in s_info.columns if c[0] in {x[0] for x in d_info.columns}]
        missing_cols = [c[0] for c in s_info.columns if c[0] not in cols]
        sums: list[list[int]] = [[0] * buckets, [0] * buckets]
        counts = [0, 0]
        for side, (conn, eng, info) in enumerate(((sc, se, s_info), (dc, de, d_info))):
            for pk, h in _scan(conn, eng, info, cols, chunk):
                b = bucket(pk, buckets)
                sums[side][b] = (sums[side][b] + h) % MOD
                counts[side] += 1
        diff_b = {b for b in range(buckets) if sums[0][b] != sums[1][b]}
        entry: dict[str, Any] = {"source_rows": counts[0], "target_rows": counts[1], "columns_compared": len(cols),
                                 "columns_not_on_target": missing_cols, "differing_buckets": len(diff_b)}
        if diff_b:
            per: list[dict[str, int]] = [{}, {}]
            for side, (conn, eng, info) in enumerate(((sc, se, s_info), (dc, de, d_info))):
                for pk, h in _scan(conn, eng, info, cols, chunk):
                    if bucket(pk, buckets) in diff_b:
                        per[side][json.dumps([norm(v) for v in pk])] = h
            keys = sorted(set(per[0]) | set(per[1]))
            entry["missing_on_target"] = [json.loads(k) for k in keys if k not in per[1]][:max_keys]
            entry["extra_on_target"] = [json.loads(k) for k in keys if k not in per[0]][:max_keys]
            entry["changed"] = [json.loads(k) for k in keys if k in per[0] and k in per[1]
                                and per[0][k] != per[1][k]][:max_keys]
        rows_match = not diff_b and counts[0] == counts[1]
        entry["rows_match"] = rows_match
        if missing_cols:  # a column the target lacks is a schema difference, not something to hide
            out["schema"].append({"table": t, "issue": "columns not on target", "columns": missing_cols})
        entry["status"] = "MATCH" if rows_match and not missing_cols else "DIFF"
        out["tables"][t] = entry
    out["status"] = "MATCH" if not out["schema"] and all(v["status"] != "DIFF" for v in out["tables"].values()) \
        else "DIFF"
    return out


def compare_documents(rows: Iterator[dict[str, Any]], fetch: Callable[[str], dict[str, Any] | None],
                      key: Callable[[dict[str, Any]], str], max_keys: int = 50) -> dict[str, Any]:
    n, missing, changed = 0, [], []
    for r in rows:
        n += 1
        k = key(r)
        d = fetch(k)
        if d is None:
            missing.append(k)
            continue
        cols = [c for c in r if c in d]
        if [norm(r[c]) for c in cols] != [norm(d[c]) for c in cols]:
            changed.append(k)
    return {"rows": n, "missing_on_target": missing[:max_keys], "changed": changed[:max_keys],
            "status": "MATCH" if not missing and not changed else "DIFF"}


def shape(docs: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, Counter[str]] = {}
    for d in docs:
        for k, v in d.items():
            out.setdefault(k, Counter())[type(norm(v)).__name__ if v is not None else "null"] += 1
    return {k: dict(v) for k, v in sorted(out.items())}


def compare_shape(src: list[dict[str, Any]], dst: list[dict[str, Any]], ignore: set[str] | None = None,
                  max_type_drift: float = 0.01) -> dict[str, Any]:
    ignore = ignore or {"_id", "id"}
    a, b = shape(src), shape(dst)
    only_src = sorted(set(a) - set(b) - ignore)
    only_dst = sorted(set(b) - set(a) - ignore)
    drift = {}
    for f in set(a) & set(b):
        na, nb = sum(a[f].values()), sum(b[f].values())
        for t in set(a[f]) | set(b[f]):
            pa, pb = a[f].get(t, 0) / na, b[f].get(t, 0) / nb
            if abs(pa - pb) > max_type_drift:
                drift[f] = {"source": a[f], "target": b[f]}
    return {"fields_only_on_source": only_src, "fields_only_on_target": only_dst, "type_drift": drift,
            "status": "MATCH" if not (only_src or only_dst or drift) else "DIFF"}


def cosine(a: list[float], b: list[float]) -> float:
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0 or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b, strict=True)) / (na * nb)


def compare_vectors(pairs: list[tuple[str, list[float], list[float]]], threshold: float = 0.99) -> dict[str, Any]:
    sims = [(k, cosine(s, f)) for k, s, f in pairs]
    low = [{"key": k, "cosine": round(c, 5)} for k, c in sims if c < threshold]
    return {"sampled": len(sims), "threshold": threshold, "below_threshold": low[:50],
            "min_cosine": round(min((c for _, c in sims), default=1.0), 5),
            "status": "MATCH" if not low else "DIFF"}


class ParityCheck(JobMachine):
    """Exact parity between two registered SQL databases (read-only on both). Result in the job state and the
    audit log. The job SUCCEEDS with verdict MATCH or DIFF (FAILED only when the comparison could not run); the
    cutover precheck (FR-06) refuses to proceed unless the verdict is MATCH."""

    kind = "parity_check"
    action = ACTION_PARITY
    title = "Parity check (FR-05)"
    first_step = "COMPARE"

    def __init__(self, registry: Any, session_factory: Any,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.registry, self._audit = registry, audit

    def fields(self) -> list[dict[str, Any]]:
        dbs = [{"value": s.name, "label": f"{s.name} ({s.engine})"} for s in self.registry.specs.values()
               if s.engine in ("postgres", "mysql", "cockroachdb")]
        return [{"name": "source", "label": "Source", "kind": "select", "required": True, "options": dbs},
                {"name": "target", "label": "Migrated copy", "kind": "select", "required": True, "options": dbs},
                {"name": "tables", "label": "Tables (comma-separated, empty = all)", "kind": "text"}]

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        s, t = self.registry.get(str(params.get("source"))), self.registry.get(str(params.get("target")))
        if s.name == t.name:
            raise ValueError("source and target must differ")
        for sp in (s, t):
            if sp.engine not in ("postgres", "mysql", "cockroachdb"):
                raise ValueError("exact parity runs on postgres, mysql or cockroachdb")
        tables = params.get("tables") or []
        if isinstance(tables, str):
            tables = [x.strip() for x in tables.split(",") if x.strip()]
        return {"source": s.name, "target": t.name, "tables": [str(x)[:63] for x in tables][:500]}

    def target_of(self, payload: dict[str, Any]) -> str:
        return f"{payload['source']} -> {payload['target']}"

    def describe(self, payload: dict[str, Any]) -> str:
        p = self.parse(payload)
        return f"read-only exact parity of {p['tables'] or 'all tables'} between {p['source']} and {p['target']}"

    def _step_compare(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        s, t = self.registry.get(payload["source"]), self.registry.get(payload["target"])
        sc, _ = self.registry.connect(s)
        try:
            dc, _ = self.registry.connect(t)
            try:
                st["result"] = compare_exact((sc, s.engine, s.database), (dc, t.engine, t.database),
                                             payload["tables"] or None)
            finally:
                dc.close()
        finally:
            sc.close()
        # A completed comparison is a SUCCEEDED job whatever the verdict: the verdict (MATCH or DIFF) is the
        # result. FAILED means the comparison itself could not run. The cutover precheck (FR-06) requires
        # a SUCCEEDED parity job whose result is MATCH, so a DIFF still blocks the cutover.
        return "DONE"

    def finish(self, job: Any) -> None:
        if self._audit is not None:
            r = json.loads(job.state_json).get("result", {})
            self._audit(f"{self.action}.{job.status.lower()}", {"job_id": job.id, "target": job.target,
                                                               "status": r.get("status")})
