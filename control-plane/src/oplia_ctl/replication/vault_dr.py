"""Vault / OpenBao DR: integrated-storage (Raft) snapshots copied to the DR object store, optional restore.

Works with open-source Vault and OpenBao (both serve ``/v1/sys/storage/raft/snapshot``). Vault
Enterprise *performance* and *DR replication* (``/v1/sys/replication/*``) need an Enterprise licence
and OpenBao has no equivalent, so this module does not use them; with an Enterprise licence those
are configured in Vault itself and this module still provides independent, verified snapshots.

``dr.vault_snapshot`` job steps (``oplia-dr-job-worker``):

1. ``SNAPSHOT`` - stream the source snapshot to a local temp file while computing SHA-256 (the file is
   a gzip archive; anything else is refused), upload it to the DR store encrypted with the target
   key (``key_ref``) with the SHA-256 as a tag, then read it back and compare the SHA-256.
2. ``RESTORE`` (only when the setting ``allow_restore`` is on *and* the proposal asks for it) - read the
   snapshot back from the store, verify SHA-256 again, and ``POST /v1/sys/storage/raft/snapshot-force``
   to the DR cluster. *This replaces all data in the DR cluster.*
3. ``CHECK`` - ``GET /v1/sys/health`` on the DR cluster and record ``initialized`` / ``sealed``. A
   snapshot from another cluster carries that cluster's keyring: with Shamir seals the DR cluster
   must be unsealed with the **source** cluster's unseal keys (with auto-unseal, it must reach the
   source's KMS key). The job reports this instead of hiding it.

Tokens are read from the secret store (names in the settings) and never written to the job state.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Callable
from datetime import UTC
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow
from oplia_ctl.replication.stores import Store, StoreSpec, build_store

ACTION_VAULT_SNAPSHOT = "dr.vault_snapshot"
_LOCAL = ("http://127.0.0.1:", "http://localhost:", "http://[::1]:")


class VaultEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    addr: str                                # https://vault.example:8200
    token_secret: str                        # secret NAME holding a token allowed to snapshot / restore
    ca_cert: str = ""                        # path to a CA bundle; empty = system trust

    @field_validator("addr")
    @classmethod
    def _addr(cls, v: str) -> str:
        v = v.rstrip("/")
        if not v.startswith("https://") and not v.startswith(_LOCAL):
            raise ValueError("Vault address must be https:// (plain http only for a server on localhost)")
        return v


class VaultDrSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: VaultEndpoint
    store: StoreSpec
    prefix: str = Field(default="vault-snapshots/", pattern=r"^[A-Za-z0-9._/-]*$")
    key_ref: str | None = None               # target-side key for the stored snapshot
    target: VaultEndpoint | None = None      # DR cluster (needed only for restore)
    allow_restore: bool = False
    timeout_seconds: float = Field(default=600, ge=10, le=7200)


class VaultSnapshots(JobMachine):
    kind = "vault_snapshot"
    action = ACTION_VAULT_SNAPSHOT
    title = "Vault snapshot to DR"
    first_step = "SNAPSHOT"
    secret_state_keys = ()

    def __init__(self, cfg: VaultDrSettings, session_factory: Any, secrets: Any = None,
                 store_factory: Callable[[StoreSpec], Store] = build_store,
                 transport: httpx.BaseTransport | None = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg = cfg
        self._secrets = secrets
        self._store_factory = store_factory
        self._transport = transport
        self._audit = audit
        self._store: Store | None = None

    def store(self) -> Store:
        if self._store is None:
            self._store = self._store_factory(self.cfg.store)
        return self._store

    def _http(self, ep: VaultEndpoint) -> httpx.Client:
        verify: Any = ep.ca_cert or True
        return httpx.Client(base_url=ep.addr, timeout=self.cfg.timeout_seconds, transport=self._transport,
                            verify=verify, headers={"X-Vault-Token": str(self._secrets.get(ep.token_secret))})

    # --------------------------------------------------------------- module interface
    def fields(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if self.cfg.allow_restore and self.cfg.target is not None:
            out.append({"name": "restore", "label": "Also restore into the DR Vault (replaces ALL its data)",
                        "kind": "checkbox", "initial": False})
        return out

    def summary(self) -> dict[str, Any]:
        return {"source": self.cfg.source.addr, "store": f"{self.cfg.store.cloud}:{self.cfg.store.bucket}/"
                f"{self.cfg.prefix}", "restore": (self.cfg.target.addr if self.cfg.allow_restore and self.cfg.target
                                                   else "disabled")}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        r = params.get("restore", False)
        restore = r if isinstance(r, bool) else str(r).lower() in ("1", "true", "yes", "on")
        if restore and not (self.cfg.allow_restore and self.cfg.target is not None):
            raise ValueError("restore is not enabled for this control plane (allow_restore and target)")
        return {"restore": restore}

    def target_of(self, payload: dict[str, Any]) -> str:
        return self.cfg.source.addr

    def describe(self, payload: dict[str, Any]) -> str:
        c = self.parse(payload)
        text = (f"Raft snapshot of {self.cfg.source.addr} to {self.cfg.store.cloud}:{self.cfg.store.bucket}/"
                f"{self.cfg.prefix} (SHA-256 verified after upload)")
        if c["restore"] and self.cfg.target is not None:
            text += (f", then FORCE-RESTORE it into {self.cfg.target.addr}: replaces all data there; the DR "
                     f"cluster then needs the source cluster's unseal keys or KMS key")
        return text

    # --------------------------------------------------------------- steps
    def _step_snapshot(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        h = hashlib.sha256()
        size = 0
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "vault.snap")
            with self._http(self.cfg.source) as c, c.stream("GET", "/v1/sys/storage/raft/snapshot") as r:
                if r.status_code != 200:
                    r.read()
                    raise RuntimeError(f"snapshot request failed with HTTP {r.status_code}: {r.text[:300]}")
                with open(path, "wb") as fh:
                    for chunk in r.iter_bytes(1 << 20):
                        h.update(chunk)
                        size += len(chunk)
                        fh.write(chunk)
            with open(path, "rb") as fh:
                if fh.read(2) != b"\x1f\x8b":
                    raise RuntimeError("the snapshot is not a gzip archive (is the source on integrated storage?)")
            digest = h.hexdigest()
            key = f"{self.cfg.prefix}oplia-vault-{self._now().astimezone(UTC):%Y%m%dT%H%M%SZ}-{job.id[:8]}.snap"
            with open(path, "rb") as fh:
                self.store().put(key, fh, size, self.cfg.key_ref, {"sha256": digest, "oplia-dr-job": job.id})
        info = self.store().head(key)
        if info is None or info.size != size:
            raise RuntimeError(f"stored snapshot {key} has size {info.size if info else None}, expected {size}")
        if self._sha_of(key) != digest:
            raise RuntimeError(f"stored snapshot {key} does not match the SHA-256 of the downloaded snapshot")
        st.update(key=key, size=size, sha256=digest, stored=True)
        return "RESTORE" if payload.get("restore") else "DONE"

    def _sha_of(self, key: str) -> str:
        h = hashlib.sha256()
        r = self.store().open(key)
        while chunk := r.read(1 << 20):
            h.update(chunk)
        return h.hexdigest()

    def _step_restore(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        tgt = self.cfg.target
        if tgt is None or not self.cfg.allow_restore:
            raise RuntimeError("restore was disabled after the proposal was approved")
        r = self.store().open(st["key"])
        data = bytearray()
        while chunk := r.read(1 << 20):
            data += chunk
        if hashlib.sha256(data).hexdigest() != st["sha256"]:
            raise RuntimeError("snapshot in the store changed since it was taken: not restoring")
        with self._http(tgt) as c:
            resp = c.post("/v1/sys/storage/raft/snapshot-force", content=bytes(data),
                          headers={"Content-Type": "application/octet-stream"})
        if resp.status_code not in (200, 204):
            raise RuntimeError(f"restore failed with HTTP {resp.status_code}: {resp.text[:300]}")
        st["restored_to"] = tgt.addr
        return "CHECK"

    def _step_check(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        tgt = self.cfg.target
        if tgt is None:
            raise RuntimeError("no target configured")
        with httpx.Client(base_url=tgt.addr, timeout=30, transport=self._transport,
                          verify=tgt.ca_cert or True) as c:
            h = c.get("/v1/sys/health", params={"standbyok": "true", "sealedcode": "200",
                                                  "uninitcode": "200"}).json()
        st["target_health"] = {k: h.get(k) for k in ("initialized", "sealed", "standby", "version")}
        if h.get("sealed"):
            st["action_needed"] = ("DR Vault is sealed after the restore: unseal it with the SOURCE cluster's "
                                   "unseal keys (or give it access to the source's auto-unseal key)")
        return "DONE"

    def finish(self, job: DrJobRow) -> None:
        if self._audit is not None:
            st = self._public(job)["state"]
            self._audit("dr_vault_snapshot", {"job_id": job.id, "status": job.status, "key": st.get("key"),
                                              "size": st.get("size"), "sha256": st.get("sha256"),
                                              "restored_to": st.get("restored_to"),
                                              "target_health": st.get("target_health"), "error": job.error})
