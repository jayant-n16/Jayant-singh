"""Kubernetes backup and cross-cloud restore with Velero.

A ``dr.k8s_backup`` proposal names a configured *plan* (source cluster -> DR cluster) and the
namespaces to protect. The ``oplia-dr-job-worker`` then advances, one saved step per run:

``BACKUP`` -> ``WAIT_BACKUP`` -> [``WAIT_SYNC`` -> ``RESTORE`` -> ``WAIT_RESTORE``] -> ``DONE``

* ``BACKUP`` creates a ``velero.io/v1 Backup`` in the source cluster. Volume data goes into the
  backup storage location (object storage), because cloud-native volume snapshots cannot be restored
  in another cloud: ``fs-backup`` (Kopia file-system backup through the node agent) or ``data-mover``
  (CSI snapshot whose data Velero moves to the storage location). Native snapshot mode is refused.
* ``WAIT_SYNC`` waits until the DR cluster's Velero has synced the backup from its own storage
  location (a read-only location on the replicated bucket - the object replication pairs keep it in
  step, or a bucket both clusters can read) and reports it ``Completed``.
* ``RESTORE`` creates a ``Restore`` in the DR cluster with ``existingResourcePolicy: none`` (existing
  objects are never overwritten), optional namespace mapping, and PV restore.

Failures (``Failed``, ``PartiallyFailed``, ``FailedValidation``) fail the job with Velero's error
and warning counts; every job ends with a ``dr_k8s_backup`` audit event. Velero (with node agent
and the provider plugin) must already be installed in both clusters; OPLIA does not install it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow

ACTION_K8S_BACKUP = "dr.k8s_backup"
GROUP, VERSION = "velero.io", "v1"
_NS = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
FAILED_PHASES = ("Failed", "PartiallyFailed", "FailedValidation", "FinalizingPartiallyFailed")


class Cluster(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kubeconfig_secret: str = ""        # secret NAME holding a kubeconfig; empty = in-cluster service account
    context: str = ""
    velero_namespace: str = "velero"


class VeleroPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,30}$")
    source: str                        # cluster name
    target: str                        # DR cluster name
    namespaces: list[str] = Field(min_length=1)    # namespaces this plan may back up
    storage_location: str = "default"              # BSL in the source cluster
    volume_mode: Literal["fs-backup", "data-mover"] = "fs-backup"
    ttl: str = Field(default="720h0m0s", pattern=r"^(\d+h)?(\d+m)?(\d+s)?$")
    backup_timeout_seconds: int = Field(default=7200, ge=60, le=86400)
    sync_timeout_seconds: int = Field(default=1800, ge=60, le=86400)
    restore_timeout_seconds: int = Field(default=7200, ge=60, le=86400)

    @field_validator("namespaces")
    @classmethod
    def _names(cls, v: list[str]) -> list[str]:
        for n in v:
            if not _NS.match(n) or len(n) > 63:
                raise ValueError(f"invalid namespace {n!r}")
        return v


class VeleroSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    clusters: dict[str, Cluster] = Field(min_length=1)
    plans: list[VeleroPlan] = Field(min_length=1)

    def model_post_init(self, _ctx: Any) -> None:
        for p in self.plans:
            for c in (p.source, p.target):
                if c not in self.clusters:
                    raise ValueError(f"plan {p.name}: unknown cluster {c!r}")
            if p.source == p.target:
                raise ValueError(f"plan {p.name}: source and target cluster must differ")


def _api_for(cluster: Cluster, secrets: Any) -> Any:  # pragma: no cover - real client wiring
    import yaml
    from kubernetes import client, config
    if cluster.kubeconfig_secret:
        cfg = yaml.safe_load(str(secrets.get(cluster.kubeconfig_secret)))
        api_client = config.new_client_from_config_dict(cfg, context=cluster.context or None)  # type: ignore[no-untyped-call]
        return client.CustomObjectsApi(api_client)
    config.load_incluster_config()  # type: ignore[no-untyped-call]
    return client.CustomObjectsApi()


def _mapping(v: Any) -> dict[str, str]:
    pairs: list[tuple[str, ...]]
    if isinstance(v, dict):
        pairs = [(str(a), str(b)) for a, b in v.items()]
    else:
        pairs = [tuple(p.split(":", 1)) for p in str(v or "").replace("\n", ",").split(",") if p.strip()]
    out: dict[str, str] = {}
    for p in pairs:
        if len(p) != 2:
            raise ValueError("namespace mapping must be source:target pairs")
        a, b = (str(x).strip() for x in p)
        if not _NS.match(a) or not _NS.match(b):
            raise ValueError(f"invalid namespace mapping {a}:{b}")
        out[a] = b
    return out


class VeleroBackups(JobMachine):
    kind = "k8s_backup"
    action = ACTION_K8S_BACKUP
    title = "Kubernetes backup and DR restore"
    first_step = "BACKUP"

    def __init__(self, cfg: VeleroSettings, session_factory: Any, secrets: Any = None,
                 api_factory: Callable[[str], Any] | None = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg = cfg
        self.plans = {p.name: p for p in cfg.plans}
        self._audit = audit
        self._api_factory = api_factory or (lambda name: _api_for(cfg.clusters[name], secrets))
        self._apis: dict[str, Any] = {}

    def _api(self, cluster: str) -> Any:
        if cluster not in self._apis:
            self._apis[cluster] = self._api_factory(cluster)
        return self._apis[cluster]

    # ----------------------------------------------------------------- module interface
    def fields(self) -> list[dict[str, Any]]:
        return [
            {"name": "plan", "label": "Plan", "kind": "select", "required": True,
             "options": [{"value": p.name, "label": f"{p.name}: {p.source} → {p.target} ({p.volume_mode})"}
                         for p in self.cfg.plans]},
            {"name": "namespaces", "label": "Namespaces", "kind": "text", "required": True, "maxLength": 1000,
             "help": "Comma separated; must be allowed by the plan"},
            {"name": "restore", "label": "Also restore into the DR cluster", "kind": "checkbox", "initial": True},
            {"name": "namespace_mapping", "label": "Namespace mapping (optional)", "kind": "text",
             "maxLength": 1000, "help": "source:target, comma separated"},
        ]

    def summary(self) -> dict[str, Any]:
        return {"plans": [f"{p.name}: {p.source} → {p.target}, {p.volume_mode}, namespaces "
                          f"{', '.join(p.namespaces)}" for p in self.cfg.plans]}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        plan = self.plans.get(str(params.get("plan", "")))
        if plan is None:
            raise ValueError(f"unknown backup plan {params.get('plan')!r}")
        raw = params.get("namespaces")
        ns = [str(n).strip() for n in (raw if isinstance(raw, list) else str(raw or "").split(",")) if str(n).strip()]
        if not ns:
            raise ValueError("at least one namespace")
        bad = sorted(set(ns) - set(plan.namespaces))
        if bad:
            raise ValueError(f"namespaces not allowed by plan {plan.name}: {', '.join(bad)}")
        mapping = _mapping(params.get("namespace_mapping"))
        if set(mapping) - set(ns):
            raise ValueError("namespace mapping names a namespace that is not backed up")
        restore = params.get("restore", True)
        restore = restore if isinstance(restore, bool) else str(restore).lower() in ("1", "true", "yes", "on")
        return {"plan": plan.name, "namespaces": sorted(set(ns)), "restore": restore, "namespace_mapping": mapping}

    def target_of(self, payload: dict[str, Any]) -> str:
        p = self.plans[payload["plan"]]
        return f"{p.source}->{p.target}:{','.join(payload['namespaces'])}"

    def describe(self, payload: dict[str, Any]) -> str:
        c = self.parse(payload)
        p = self.plans[c["plan"]]
        text = (f"Velero backup of {', '.join(c['namespaces'])} in {p.source} ({p.volume_mode}, storage "
                f"location {p.storage_location}, ttl {p.ttl})")
        if c["restore"]:
            text += f", then restore into {p.target} without overwriting existing objects"
            if c["namespace_mapping"]:
                text += " (mapping " + ", ".join(f"{a}→{b}" for a, b in c["namespace_mapping"].items()) + ")"
        return text

    # ----------------------------------------------------------------- bodies
    def backup_body(self, job: DrJobRow, payload: dict[str, Any]) -> dict[str, Any]:
        p = self.plans[payload["plan"]]
        spec: dict[str, Any] = {"includedNamespaces": payload["namespaces"], "storageLocation": p.storage_location,
                                "ttl": p.ttl, "snapshotVolumes": p.volume_mode == "data-mover"}
        if p.volume_mode == "fs-backup":
            spec["defaultVolumesToFsBackup"] = True
        else:
            spec["snapshotMoveData"] = True
        return {"apiVersion": f"{GROUP}/{VERSION}", "kind": "Backup",
                "metadata": {"name": self._name(job), "namespace": self.cfg.clusters[p.source].velero_namespace,
                             "labels": {"oplia-dr-job": job.id[:36], "oplia-plan": p.name}},
                "spec": spec}

    def restore_body(self, job: DrJobRow, payload: dict[str, Any]) -> dict[str, Any]:
        p = self.plans[payload["plan"]]
        spec: dict[str, Any] = {"backupName": self._name(job), "includedNamespaces": payload["namespaces"],
                                "existingResourcePolicy": "none", "restorePVs": True}
        if payload.get("namespace_mapping"):
            spec["namespaceMapping"] = payload["namespace_mapping"]
        return {"apiVersion": f"{GROUP}/{VERSION}", "kind": "Restore",
                "metadata": {"name": self._name(job), "namespace": self.cfg.clusters[p.target].velero_namespace,
                             "labels": {"oplia-dr-job": job.id[:36], "oplia-plan": p.name}},
                "spec": spec}

    def _name(self, job: DrJobRow) -> str:
        return f"oplia-{json.loads(job.payload_json)['plan']}-{job.id[:8]}"

    # ----------------------------------------------------------------- helpers
    def _get(self, cluster: str, plural: str, name: str) -> dict[str, Any] | None:
        from kubernetes.client.exceptions import ApiException
        ns = self.cfg.clusters[cluster].velero_namespace
        try:
            return dict(self._api(cluster).get_namespaced_custom_object(GROUP, VERSION, ns, plural, name))
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def _create(self, cluster: str, plural: str, body: dict[str, Any]) -> None:
        from kubernetes.client.exceptions import ApiException
        ns = self.cfg.clusters[cluster].velero_namespace
        try:
            self._api(cluster).create_namespaced_custom_object(GROUP, VERSION, ns, plural, body)
        except ApiException as exc:
            if exc.status != 409:          # 409: created by an earlier run that did not save its step
                raise

    def _elapsed(self, st: dict[str, Any], key: str) -> float:
        return (self._now() - datetime.fromisoformat(st[key])).total_seconds()

    @staticmethod
    def _result(obj: dict[str, Any]) -> dict[str, Any]:
        s = obj.get("status") or {}
        return {k: s.get(k) for k in ("phase", "errors", "warnings", "progress", "failureReason",
                                      "startTimestamp", "completionTimestamp") if s.get(k) is not None}

    # ----------------------------------------------------------------- steps
    def _step_backup(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.plans[payload["plan"]]
        self._create(p.source, "backups", self.backup_body(job, payload))
        st["backup_name"] = self._name(job)
        st["backup_started_at"] = self._now().isoformat()
        return "WAIT_BACKUP"

    def _step_wait_backup(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.plans[payload["plan"]]
        obj = self._get(p.source, "backups", st["backup_name"])
        if obj is None:
            raise RuntimeError(f"backup {st['backup_name']} disappeared from {p.source}")
        st["backup"] = self._result(obj)
        phase = st["backup"].get("phase")
        if phase in FAILED_PHASES:
            reason = st["backup"].get("failureReason")
            raise RuntimeError(f"backup {phase}: {st['backup'].get('errors', 0)} error(s), "
                               f"{st['backup'].get('warnings', 0)} warning(s){', ' + str(reason) if reason else ''}")
        if phase == "Completed":
            if not payload["restore"]:
                return "DONE"
            st["sync_started_at"] = self._now().isoformat()
            return "WAIT_SYNC"
        if self._elapsed(st, "backup_started_at") > p.backup_timeout_seconds:
            raise TimeoutError(f"backup not completed within {p.backup_timeout_seconds}s (phase {phase})")
        return "WAIT_BACKUP"

    def _step_wait_sync(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.plans[payload["plan"]]
        obj = self._get(p.target, "backups", st["backup_name"])
        if obj is not None and (obj.get("status") or {}).get("phase") == "Completed":
            st["synced"] = True
            return "RESTORE"
        if self._elapsed(st, "sync_started_at") > p.sync_timeout_seconds:
            raise TimeoutError(f"backup not visible in {p.target} within {p.sync_timeout_seconds}s: check that "
                               f"its storage location reads the replicated bucket")
        return "WAIT_SYNC"

    def _step_restore(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.plans[payload["plan"]]
        self._create(p.target, "restores", self.restore_body(job, payload))
        st["restore_name"] = self._name(job)
        st["restore_started_at"] = self._now().isoformat()
        return "WAIT_RESTORE"

    def _step_wait_restore(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.plans[payload["plan"]]
        obj = self._get(p.target, "restores", st["restore_name"])
        if obj is None:
            raise RuntimeError(f"restore {st['restore_name']} disappeared from {p.target}")
        st["restore"] = self._result(obj)
        phase = st["restore"].get("phase")
        if phase in FAILED_PHASES:
            raise RuntimeError(f"restore {phase}: {st['restore'].get('errors', 0)} error(s), "
                               f"{st['restore'].get('warnings', 0)} warning(s)")
        if phase == "Completed":
            return "DONE"
        if self._elapsed(st, "restore_started_at") > p.restore_timeout_seconds:
            raise TimeoutError(f"restore not completed within {p.restore_timeout_seconds}s (phase {phase})")
        return "WAIT_RESTORE"

    def finish(self, job: DrJobRow) -> None:
        if self._audit is None:
            return
        pub = self._public(job)
        st = pub["state"]
        self._audit("dr_k8s_backup", {"job_id": job.id, "plan": pub["payload"]["plan"],
                                      "namespaces": pub["payload"]["namespaces"], "status": job.status,
                                      "backup": st.get("backup"), "restore": st.get("restore"), "error": job.error})
