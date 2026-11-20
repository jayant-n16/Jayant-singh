"""Incremental object replication S3 <-> Azure Blob <-> GCS with SHA-256 verification.

plan(pair): list the source, compare (etag, size) with the manifest of what was replicated
before, and return the new or changed objects. A plan becomes a ``dr.object_sync`` proposal.
apply(payload): for each planned object, re-check the source etag (changed since the plan ->
skipped, picked up next run), stream it to the target hashing on the way, write it encrypted
with the target-side key and the target-mapped tags, verify the target size and (by default)
read it back and compare SHA-256. Only verified objects enter the manifest.

Deletions are never replicated automatically: objects missing at the source are reported
(``missing_at_source``) so a person decides - a DR copy must survive a deletion at the source.
A pair may opt in with ``replicate_deletions: true`` (default false). Then ``plan_deletions``
lists replicated objects that are gone at the source and a separate ``dr.object_delete``
proposal (four-eyes, kill switch) removes them from the target. The executor re-checks each key
is still absent at the source, refuses a batch larger than ``max_delete_fraction`` of the
replicated objects (a mass deletion at the source looks like an incident, not housekeeping),
and records every deleted key in the run summary.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.replication.keys import validate_key_ref
from oplia_ctl.replication.models import ObjectManifestRow, ReplicationRunRow
from oplia_ctl.replication.stores import Store, StoreSpec
from oplia_ctl.replication.streams import HashingReader
from oplia_ctl.replication.tags import map_tags

ACTION_OBJECT_SYNC = "dr.object_sync"
ACTION_OBJECT_DELETE = "dr.object_delete"
MAX_DELETES_PER_PROPOSAL = 1000


class ObjectPair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    source: StoreSpec
    target: StoreSpec
    prefix: str = ""
    target_key: str | None = None            # key reference on the target cloud (see keys.py)
    tags: dict[str, str] = Field(default_factory=dict)   # applied to every target object, mapped per cloud
    replicate_deletions: bool = False        # opt in: lets a gated proposal remove target copies
    max_delete_fraction: float = Field(default=0.1, gt=0, le=1)   # refuse batches above this share

    def model_post_init(self, _: Any) -> None:
        if self.source.cloud == self.target.cloud and self.source.bucket == self.target.bucket:
            raise ValueError(f"{self.name}: source and target are the same bucket")
        if self.target_key:
            validate_key_ref(self.target.cloud, self.target_key, "objects")


class ObjectReplicator:
    def __init__(self, pairs: list[ObjectPair], session_factory: sessionmaker[Session],
                 store_factory: Callable[[StoreSpec], Store], max_objects: int = 5000,
                 verify_readback: bool = True, now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.pairs = {p.name: p for p in pairs}
        self._sf = session_factory
        self._stores = store_factory
        self._max = max_objects
        self._verify = verify_readback
        self._now = now

    def _pair(self, name: str) -> ObjectPair:
        if name not in self.pairs:
            raise KeyError(name)
        return self.pairs[name]

    def _manifest(self, pair: str) -> dict[str, ObjectManifestRow]:
        with self._sf() as s:
            return {r.key: r for r in s.scalars(select(ObjectManifestRow).where(ObjectManifestRow.pair == pair))}

    def plan(self, name: str) -> dict[str, Any]:
        p = self._pair(name)
        man = self._manifest(name)
        todo: list[dict[str, Any]] = []
        seen: set[str] = set()
        for o in self._stores(p.source).list(p.prefix):
            seen.add(o.key)
            m = man.get(o.key)
            if m is None or m.source_etag != o.etag or m.size != o.size:
                todo.append({"key": o.key, "etag": o.etag, "size": o.size, "new": m is None})
        todo.sort(key=lambda x: x["key"])
        more = len(todo) > self._max
        todo = todo[: self._max]
        total_bytes = sum(int(x["size"]) for x in todo)
        return {"pair": name, "objects": todo, "bytes": total_bytes, "truncated": more,
                "missing_at_source": sorted(set(man) - seen)[:1000],
                "tags": map_tags(p.tags, p.target.cloud).__dict__}

    def plan_deletions(self, name: str) -> dict[str, Any]:
        """Replicated keys that no longer exist at the source (head-checked one by one)."""
        p = self._pair(name)
        if not p.replicate_deletions:
            raise PermissionError(f"pair {name} does not replicate deletions (replicate_deletions is false)")
        man = self._manifest(name)
        listed = {o.key for o in self._stores(p.source).list(p.prefix)}
        src = self._stores(p.source)
        gone = [k for k in sorted(set(man) - listed) if src.head(k) is None]
        more = len(gone) > MAX_DELETES_PER_PROPOSAL
        return {"pair": name, "keys": gone[:MAX_DELETES_PER_PROPOSAL], "truncated": more,
                "replicated_objects": len(man), "limit_fraction": p.max_delete_fraction}

    def describe(self, payload: dict[str, Any]) -> str:
        p = self._pair(str(payload.get("pair")))
        objs = payload.get("objects") or []
        return (f"Copy {len(objs)} object(s) ({sum(int(o['size']) for o in objs)} bytes) from "
                f"{p.source.cloud}:{p.source.bucket} to {p.target.cloud}:{p.target.bucket}, "
                f"encrypting with {p.target_key or 'the target default key'}, verifying SHA-256")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        p = self._pair(str(payload.get("pair")))
        src, dst = self._stores(p.source), self._stores(p.target)
        tags = map_tags(p.tags, p.target.cloud).tags
        started = self._now()
        copied, nbytes, skipped, failed = [], 0, [], []
        for o in payload.get("objects") or []:
            key = str(o["key"])
            try:
                cur = src.head(key)
                if cur is None or cur.etag != o["etag"] or cur.size != int(o["size"]):
                    skipped.append({"key": key, "reason": "changed or deleted at source since the plan"})
                    continue
                reader = HashingReader(src.open(key), limit=cur.size)
                dst.put(key, reader, cur.size, p.target_key, tags)
                if reader.count != cur.size:
                    raise RuntimeError(f"read {reader.count} of {cur.size} bytes from source")
                sha = reader.hexdigest()
                landed = dst.head(key)
                if landed is None or landed.size != cur.size:
                    raise RuntimeError(f"target size {landed.size if landed else 'missing'} != {cur.size}")
                if self._verify:
                    back = HashingReader(dst.open(key))
                    while back.read(8 * 1024 * 1024):
                        pass
                    if back.hexdigest() != sha:
                        raise RuntimeError("SHA-256 of the target copy differs from the source stream")
                self._record(p.name, key, cur.etag, cur.size, sha)
                copied.append({"key": key, "sha256": sha, "size": cur.size})
                nbytes += cur.size
            except Exception as exc:
                failed.append({"key": key, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
        status = "FAILED" if failed and not copied else "PARTIAL" if failed or skipped else "OK"
        summary = {"copied": len(copied), "skipped": skipped[:200], "failed": failed[:200]}
        with self._sf() as s, s.begin():
            s.add(ReplicationRunRow(id=str(uuid.uuid4()), pair=p.name, started_at=started, finished_at=self._now(),
                                    status=status, copied=len(copied), bytes=nbytes,
                                    summary_json=json.dumps(summary)))
        result = {"pair": p.name, "status": status, "bytes": nbytes, **summary}
        if failed and not copied:
            raise RuntimeError(json.dumps(result)[:2000])
        return result

    def _delete_guard(self, p: ObjectPair, keys: list[str]) -> None:
        if not p.replicate_deletions:
            raise PermissionError(f"pair {p.name} does not replicate deletions (replicate_deletions is false)")
        if not keys or len(keys) > MAX_DELETES_PER_PROPOSAL:
            raise ValueError(f"1 to {MAX_DELETES_PER_PROPOSAL} keys per deletion proposal")
        total = len(self._manifest(p.name))
        if total == 0 or len(keys) > p.max_delete_fraction * total:
            raise PermissionError(f"refusing to delete {len(keys)} of {total} replicated objects "
                                  f"(limit {p.max_delete_fraction:.0%}); investigate the source first")

    def describe_delete(self, payload: dict[str, Any]) -> str:
        p = self._pair(str(payload.get("pair")))
        keys = [str(k) for k in payload.get("keys") or []]
        self._delete_guard(p, keys)
        return (f"Delete {len(keys)} object(s) from {p.target.cloud}:{p.target.bucket} that no longer exist at "
                f"{p.source.cloud}:{p.source.bucket} (each re-checked at the source first)")

    def delete(self, payload: dict[str, Any]) -> dict[str, Any]:
        p = self._pair(str(payload.get("pair")))
        keys = [str(k) for k in payload.get("keys") or []]
        self._delete_guard(p, keys)
        src, dst = self._stores(p.source), self._stores(p.target)
        man = self._manifest(p.name)
        started = self._now()
        deleted, skipped, failed = [], [], []
        for key in keys:
            try:
                if key not in man:
                    skipped.append({"key": key, "reason": "not in the replication manifest"})
                    continue
                if src.head(key) is not None:
                    skipped.append({"key": key, "reason": "exists at the source again"})
                    continue
                if dst.head(key) is not None:
                    dst.delete(key)
                    if dst.head(key) is not None:
                        raise RuntimeError("object still present at the target after delete")
                with self._sf() as s, s.begin():
                    s.execute(delete(ObjectManifestRow).where(ObjectManifestRow.pair == p.name,
                                                              ObjectManifestRow.key == key))
                deleted.append(key)
            except Exception as exc:
                failed.append({"key": key, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
        status = "FAILED" if failed and not deleted else "PARTIAL" if failed or skipped else "OK"
        summary = {"deleted": deleted[:1000], "skipped": skipped[:200], "failed": failed[:200]}
        with self._sf() as s, s.begin():
            s.add(ReplicationRunRow(id=str(uuid.uuid4()), pair=p.name, started_at=started, finished_at=self._now(),
                                    status=status, copied=0, bytes=0,
                                    summary_json=json.dumps({"kind": "delete", **summary})))
        result = {"pair": p.name, "status": status, **summary}
        if failed and not deleted:
            raise RuntimeError(json.dumps(result)[:2000])
        return result

    def deletion_executor(self) -> DeletionExecutor:
        return DeletionExecutor(self)

    def _record(self, pair: str, key: str, etag: str, size: int, sha: str) -> None:
        with self._sf() as s, s.begin():
            s.execute(delete(ObjectManifestRow).where(ObjectManifestRow.pair == pair, ObjectManifestRow.key == key))
            s.add(ObjectManifestRow(id=str(uuid.uuid4()), pair=pair, key=key, source_etag=etag, size=size,
                                    sha256=sha, replicated_at=self._now()))

    def status(self) -> list[dict[str, Any]]:
        out = []
        with self._sf() as s:
            for name, p in sorted(self.pairs.items()):
                last = s.scalars(select(ReplicationRunRow).where(ReplicationRunRow.pair == name)
                                 .order_by(ReplicationRunRow.started_at.desc()).limit(1)).first()
                n = len(s.scalars(select(ObjectManifestRow.id).where(ObjectManifestRow.pair == name)).all())
                out.append({"pair": name, "source": f"{p.source.cloud}:{p.source.bucket}/{p.prefix}",
                            "target": f"{p.target.cloud}:{p.target.bucket}", "target_key": p.target_key,
                            "replicate_deletions": p.replicate_deletions,
                            "replicated_objects": n,
                            "last_run": None if last is None else {
                                "status": last.status, "started_at": last.started_at.isoformat(),
                                "copied": last.copied, "bytes": last.bytes,
                                "summary": json.loads(last.summary_json)}})
        return out


class DeletionExecutor:
    """Gate executor for ``dr.object_delete`` (separate from the copy executor)."""

    def __init__(self, rep: ObjectReplicator) -> None:
        self._rep = rep

    def describe(self, payload: dict[str, Any]) -> str:
        return self._rep.describe_delete(payload)

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._rep.delete(payload)
