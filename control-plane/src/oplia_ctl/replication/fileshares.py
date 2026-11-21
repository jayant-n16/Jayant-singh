"""File-share replication: Amazon EFS <-> Azure Files <-> Google Filestore.

None of the three services offers an API that returns file contents across clouds (EFS and
Filestore are NFS servers; Azure Files is SMB/NFS). So the shares are **mounted** into the DR worker
pod by their Kubernetes CSI drivers (EFS CSI, Azure Files CSI, Filestore CSI) and this module copies
between the two mount paths:

``PLAN``   - walk the source; a file is copied when it is missing at the target or its size or
             mtime differs from what was last replicated (manifest kept in the job state per run and
             in ``state_file`` on the target between runs). Symlinks are recreated as symlinks
             (target text unchanged) and never followed; other special files are reported.
``COPY``   - at most ``max_files_per_run`` files per step: stream to ``.<name>.oplia-tmp`` in the
             target directory, SHA-256 while streaming, fsync, re-hash the written file, then an atomic
             rename and the source mtime/mode are applied. A source changed during the copy (size or
             mtime moved) is retried in the next run, not written.
``VERIFY`` - every copied file is re-hashed at the target and compared with the source hash.

Files deleted at the source are reported and never deleted at the target. Paths that would leave
the target root (``..``, absolute links) are refused. Ownership (uid/gid) and ACLs are not copied:
NFS and SMB identities do not map between clouds; this is reported once per run.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow

ACTION_FILESHARE = "dr.fileshare_sync"
STATE_FILE = ".oplia-replication.json"
_CHUNK = 1024 * 1024


class SharePair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    source_kind: str = Field(pattern=r"^(efs|azure_files|filestore)$")
    target_kind: str = Field(pattern=r"^(efs|azure_files|filestore)$")
    source_path: str
    target_path: str
    max_files_per_run: int = Field(default=2000, ge=1, le=100000)

    def model_post_init(self, _ctx: Any) -> None:
        for p in (self.source_path, self.target_path):
            if not os.path.isabs(p):
                raise ValueError(f"{self.name}: mount paths must be absolute, got {p!r}")
        s, t = os.path.realpath(self.source_path), os.path.realpath(self.target_path)
        if s == t or t.startswith(s + os.sep) or s.startswith(t + os.sep):
            raise ValueError(f"{self.name}: source and target mounts must not overlap")


class FileShareSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pairs: list[SharePair] = Field(min_length=1)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(_CHUNK), b""):
            h.update(b)
    return h.hexdigest()


def _inside(root: Path, rel: str) -> Path:
    p = root / rel
    r = os.path.normpath(root)
    if os.path.isabs(rel) or ".." in Path(rel).parts or os.path.commonpath([r, os.path.normpath(p)]) != r:
        raise ValueError(f"path {rel!r} leaves the share root")
    return p


class FileShareReplicator(JobMachine):
    kind = "fileshare_sync"
    action = ACTION_FILESHARE
    title = "File-share replication"
    first_step = "PLAN"

    def __init__(self, cfg: FileShareSettings, session_factory: Any,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg = cfg
        self.pairs = {p.name: p for p in cfg.pairs}
        self._audit = audit

    def fields(self) -> list[dict[str, Any]]:
        return [{"name": "pair", "label": "Share pair", "kind": "select", "required": True,
                 "options": [{"value": p.name, "label": f"{p.name}: {p.source_kind} -> {p.target_kind}"}
                             for p in self.cfg.pairs]}]

    def summary(self) -> dict[str, Any]:
        return {"pairs": [f"{p.name}: {p.source_kind} -> {p.target_kind}" for p in self.cfg.pairs]}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        if str(params.get("pair", "")) not in self.pairs:
            raise ValueError(f"unknown file-share pair {params.get('pair')!r}")
        return {"pair": str(params["pair"])}

    def target_of(self, payload: dict[str, Any]) -> str:
        return str(payload["pair"])

    def describe(self, payload: dict[str, Any]) -> str:
        p = self.pairs[self.parse(payload)["pair"]]
        return (f"copy new and changed files from {p.source_kind} ({p.source_path}) to {p.target_kind} "
                f"({p.target_path}) with SHA-256 verification; deletions are reported, not copied")

    # ------------------------------------------------------------------ helpers
    def _manifest(self, p: SharePair) -> dict[str, Any]:
        f = Path(p.target_path) / STATE_FILE
        if not f.exists():
            return {}
        data = json.loads(f.read_text())
        return dict(data.get("files", {}))

    def _save_manifest(self, p: SharePair, files: dict[str, Any]) -> None:
        f = Path(p.target_path) / STATE_FILE
        tmp = f.with_name(f".{STATE_FILE}.tmp")
        tmp.write_text(json.dumps({"files": files}, sort_keys=True))
        os.replace(tmp, f)

    # ------------------------------------------------------------------ steps
    def _step_plan(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        src = Path(p.source_path)
        if not src.is_dir() or not Path(p.target_path).is_dir():
            raise FileNotFoundError(f"{p.name}: source or target mount is not a directory (is the share mounted?)")
        seen = self._manifest(p)
        todo, links, skipped, present = [], [], [], set()
        for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
            for n in list(dirnames):
                full = Path(dirpath) / n
                if full.is_symlink():
                    dirnames.remove(n)
                    filenames.append(n)
            for n in filenames:
                full = Path(dirpath) / n
                rel = str(full.relative_to(src))
                if rel == STATE_FILE:
                    continue
                present.add(rel)
                s = full.lstat()
                if stat.S_ISLNK(s.st_mode):
                    links.append({"path": rel, "to": os.readlink(full)})
                elif stat.S_ISREG(s.st_mode):
                    prev = seen.get(rel)
                    if prev is None or prev["size"] != s.st_size or prev["mtime_ns"] != s.st_mtime_ns \
                            or not (Path(p.target_path) / rel).exists():
                        todo.append({"path": rel, "size": s.st_size, "mtime_ns": s.st_mtime_ns})
                else:
                    skipped.append({"path": rel, "reason": "special file (device, FIFO or socket)"})
        st["todo"], st["links"], st["skipped"] = todo, links, skipped
        st["deleted_at_source"] = sorted(set(seen) - present)
        st["copied"], st["changed_during_copy"] = [], []
        st["notes"] = ["ownership (uid/gid) and ACLs are not copied between clouds"]
        return "COPY"

    def _step_copy(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        src, dst = Path(p.source_path), Path(p.target_path)
        batch, st["todo"] = st["todo"][:p.max_files_per_run], st["todo"][p.max_files_per_run:]
        for item in batch:
            rel = item["path"]
            s_path, t_path = _inside(src, rel), _inside(dst, rel)
            t_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = t_path.with_name(f".{t_path.name}.oplia-tmp")
            h = hashlib.sha256()
            with s_path.open("rb") as fi, tmp.open("wb") as fo:
                for b in iter(lambda: fi.read(_CHUNK), b""):
                    h.update(b)
                    fo.write(b)
                fo.flush()
                os.fsync(fo.fileno())
            after = s_path.stat()
            if after.st_size != item["size"] or after.st_mtime_ns != item["mtime_ns"]:
                tmp.unlink()
                st["changed_during_copy"].append(rel)
                continue
            digest = h.hexdigest()
            if _sha256(tmp) != digest:
                tmp.unlink()
                raise OSError(f"{rel}: the written copy does not match the source SHA-256")
            os.replace(tmp, t_path)
            os.chmod(t_path, stat.S_IMODE(after.st_mode))
            os.utime(t_path, ns=(after.st_atime_ns, after.st_mtime_ns))
            st["copied"].append({**item, "sha256": digest})
        if not st["todo"]:
            for ln in st["links"]:
                t_path = _inside(dst, ln["path"])
                if os.path.isabs(ln["to"]) or ".." in Path(ln["to"]).parts:
                    st["skipped"].append({"path": ln["path"], "reason": f"symlink to {ln['to']!r} leaves the share"})
                    continue
                t_path.parent.mkdir(parents=True, exist_ok=True)
                if t_path.is_symlink() and os.readlink(t_path) == ln["to"]:
                    continue
                if t_path.is_symlink() or t_path.exists():
                    t_path.unlink()
                os.symlink(ln["to"], t_path)
            return "VERIFY"
        return "COPY"

    def _step_verify(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        dst = Path(p.target_path)
        bad = [c["path"] for c in st["copied"] if _sha256(_inside(dst, c["path"])) != c["sha256"]]
        if bad:
            raise OSError(f"target files changed or corrupted after copy: {bad[:20]}")
        files = self._manifest(p)
        for c in st["copied"]:
            files[c["path"]] = {"size": c["size"], "mtime_ns": c["mtime_ns"], "sha256": c["sha256"]}
        self._save_manifest(p, files)
        st["verified"] = len(st["copied"])
        st["copied_count"] = len(st["copied"])
        st["copied"] = [c["path"] for c in st["copied"][:200]]  # keep job state small
        return "DONE"

    def finish(self, job: DrJobRow) -> None:
        if self._audit is not None:
            pub = self._public(job)
            stt = pub["state"]
            self._audit("dr_fileshare_sync", {
                "job_id": job.id, "pair": pub["payload"]["pair"], "status": job.status, "error": job.error,
                "copied": stt.get("copied_count"), "deleted_at_source": len(stt.get("deleted_at_source") or []),
                "changed_during_copy": stt.get("changed_during_copy"), "skipped": stt.get("skipped")})
