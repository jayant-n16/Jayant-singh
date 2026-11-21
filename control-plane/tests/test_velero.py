"""Velero backup / cross-cluster restore jobs.

The Kubernetes API is a fake CustomObjectsApi; every Backup and Restore the module creates is
validated against Velero v1.16.1's own CRD schemas (tests/fixtures/velero, from the velero
repository at tag v1.16.1) with scripts/validate-crs.py's strict checker. No cluster is used.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from kubernetes.client.exceptions import ApiException

from oplia_ctl.replication.config import ReplicationSettings, build_job_machines
from oplia_ctl.replication.velero import VeleroBackups, VeleroSettings

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("validate_crs", ROOT / "scripts" / "validate-crs.py")
assert _spec and _spec.loader
validate_crs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate_crs)
SCHEMAS = {}
for f in (ROOT / "tests" / "fixtures" / "velero").glob("*.yaml"):
    SCHEMAS.update(validate_crs.load_crds(str(f)))

CFG = VeleroSettings.model_validate({
    "clusters": {"aws-prod": {"kubeconfig_secret": "kube_aws"}, "gcp-dr": {"kubeconfig_secret": "kube_gcp"}},
    "plans": [{"name": "payments", "source": "aws-prod", "target": "gcp-dr",
               "namespaces": ["payments", "ledger"], "volume_mode": "data-mover",
               "backup_timeout_seconds": 600, "sync_timeout_seconds": 300}]})


def _validate(body: dict) -> None:
    group, _, version = body["apiVersion"].rpartition("/")
    schema = dict(SCHEMAS[(group, body["kind"], version)])
    props = dict(schema["properties"])
    props.update(apiVersion={"type": "string"}, kind={"type": "string"}, metadata={"type": "object"})
    schema["properties"] = props
    errors = [e.message for e in Draft7Validator(validate_crs._strict(schema)).iter_errors(body)]
    assert not errors, errors


class FakeK8s:
    def __init__(self):
        self.objs: dict[tuple[str, str], dict] = {}
        self.created: list[dict] = []

    def create_namespaced_custom_object(self, group, version, ns, plural, body):
        assert (group, version, ns) == ("velero.io", "v1", "velero")
        key = (plural, body["metadata"]["name"])
        if key in self.objs:
            raise ApiException(status=409)
        _validate(body)
        self.created.append(body)
        self.objs[key] = {**body, "status": {"phase": "New"}}

    def get_namespaced_custom_object(self, group, version, ns, plural, name):
        if (plural, name) not in self.objs:
            raise ApiException(status=404)
        return self.objs[(plural, name)]

    def set_phase(self, plural, name, phase, **extra):
        self.objs[(plural, name)]["status"] = {"phase": phase, **extra}


@pytest.fixture
def k8s():
    return {"aws-prod": FakeK8s(), "gcp-dr": FakeK8s()}


def _vb(session_factory, clock, k8s, events=None):
    return VeleroBackups(CFG, session_factory, api_factory=lambda c: k8s[c], now=clock,
                         audit=(lambda e, d: events.append((e, d))) if events is not None else None)


def test_backup_sync_restore_happy_path(session_factory, clock, k8s):
    events: list = []
    vb = _vb(session_factory, clock, k8s, events)
    payload = vb.parse({"plan": "payments", "namespaces": "payments, ledger", "restore": True,
                        "namespace_mapping": "ledger:ledger-dr"})
    assert "without overwriting existing objects" in vb.describe(payload) and "ledger→ledger-dr" in vb.describe(payload)
    jid = vb.queue(vb.target_of(payload), payload, "ann")["job_id"]
    vb.run_pending()
    name = vb.get(jid)["state"]["backup_name"]
    assert name == f"oplia-payments-{jid[:8]}" and vb.get(jid)["step"] == "WAIT_BACKUP"
    b = k8s["aws-prod"].created[0]["spec"]
    assert b["includedNamespaces"] == ["ledger", "payments"] and b["snapshotMoveData"] is True
    assert "defaultVolumesToFsBackup" not in b and b["storageLocation"] == "default"

    k8s["aws-prod"].set_phase("backups", name, "InProgress")
    vb.run_pending()
    k8s["aws-prod"].set_phase("backups", name, "Completed", warnings=2, errors=0)
    vb.run_pending()
    assert vb.get(jid)["step"] == "WAIT_SYNC"                 # not yet visible in the DR cluster
    k8s["gcp-dr"].objs[("backups", name)] = {"status": {"phase": "Completed"}}   # Velero's BSL sync
    vb.run_pending()
    r = k8s["gcp-dr"].created[0]
    assert r["kind"] == "Restore" and r["spec"]["backupName"] == name
    assert r["spec"]["existingResourcePolicy"] == "none" and r["spec"]["namespaceMapping"] == {"ledger": "ledger-dr"}
    k8s["gcp-dr"].set_phase("restores", name, "Completed", warnings=1)
    vb.run_pending()
    job = vb.get(jid)
    assert job["status"] == "SUCCEEDED" and job["state"]["backup"]["warnings"] == 2
    assert events[-1][0] == "dr_k8s_backup" and events[-1][1]["restore"]["phase"] == "Completed"


def test_fs_backup_mode_and_backup_only(session_factory, clock, k8s):
    cfg = VeleroSettings.model_validate({**CFG.model_dump(), "plans": [{**CFG.plans[0].model_dump(),
                                                                       "volume_mode": "fs-backup"}]})
    vb = VeleroBackups(cfg, session_factory, api_factory=lambda c: k8s[c], now=clock)
    jid = vb.queue("t", vb.parse({"plan": "payments", "namespaces": "payments", "restore": False}), "a")["job_id"]
    vb.run_pending()
    spec = k8s["aws-prod"].created[0]["spec"]
    assert spec["defaultVolumesToFsBackup"] is True and spec["snapshotVolumes"] is False
    k8s["aws-prod"].set_phase("backups", vb.get(jid)["state"]["backup_name"], "Completed")
    vb.run_pending()
    assert vb.get(jid)["status"] == "SUCCEEDED" and not k8s["gcp-dr"].created


def test_partially_failed_backup_fails_the_job(session_factory, clock, k8s):
    events: list = []
    vb = _vb(session_factory, clock, k8s, events)
    jid = vb.queue("t", vb.parse({"plan": "payments", "namespaces": "payments"}), "a")["job_id"]
    vb.run_pending()
    k8s["aws-prod"].set_phase("backups", vb.get(jid)["state"]["backup_name"], "PartiallyFailed", errors=3, warnings=1)
    vb.run_pending()
    job = vb.get(jid)
    assert job["status"] == "FAILED" and "PartiallyFailed: 3 error(s), 1 warning(s)" in job["error"]
    assert not k8s["gcp-dr"].created and events[-1][1]["status"] == "FAILED"


def test_sync_timeout_names_the_storage_location(session_factory, clock, k8s):
    vb = _vb(session_factory, clock, k8s)
    jid = vb.queue("t", vb.parse({"plan": "payments", "namespaces": "payments"}), "a")["job_id"]
    vb.run_pending()
    k8s["aws-prod"].set_phase("backups", vb.get(jid)["state"]["backup_name"], "Completed")
    vb.run_pending()
    clock.advance(seconds=301)
    vb.run_pending()
    job = vb.get(jid)
    assert job["status"] == "FAILED" and "storage location" in job["error"] and not k8s["gcp-dr"].created


def test_create_is_idempotent_after_a_crash(session_factory, clock, k8s):
    vb = _vb(session_factory, clock, k8s)
    payload = vb.parse({"plan": "payments", "namespaces": "payments"})
    jid = vb.queue("t", payload, "a")["job_id"]
    job = vb._load(jid)
    body = vb.backup_body(job, payload)
    k8s["aws-prod"].create_namespaced_custom_object("velero.io", "v1", "velero", "backups", body)
    vb.run_pending()                               # Backup already exists (409): carries on waiting
    assert vb.get(jid)["step"] == "WAIT_BACKUP" and len(k8s["aws-prod"].created) == 1


def test_parse_rejections():
    vb = VeleroBackups(CFG, session_factory=None, api_factory=lambda c: None)
    with pytest.raises(ValueError, match="not allowed by plan"):
        vb.parse({"plan": "payments", "namespaces": "payments,kube-system"})
    with pytest.raises(ValueError, match="unknown backup plan"):
        vb.parse({"plan": "nope", "namespaces": "payments"})
    with pytest.raises(ValueError, match="not backed up"):
        vb.parse({"plan": "payments", "namespaces": "payments", "namespace_mapping": "ledger:x"})
    with pytest.raises(ValueError, match="at least one"):
        vb.parse({"plan": "payments", "namespaces": " "})
    with pytest.raises(ValueError, match="must differ"):
        VeleroSettings.model_validate({**CFG.model_dump(), "plans": [{**CFG.plans[0].model_dump(),
                                                                     "target": "aws-prod"}]})
    with pytest.raises(ValueError, match="unknown cluster"):
        VeleroSettings.model_validate({**CFG.model_dump(), "plans": [{**CFG.plans[0].model_dump(),
                                                                     "target": "azure-dr"}]})


def test_settings_build_all_job_modules(monkeypatch, session_factory):
    monkeypatch.setenv("OPLIA_REPLICATION_VELERO", CFG.model_dump_json())
    assert "k8s_backup" in build_job_machines(ReplicationSettings(), session_factory)


def test_schema_check_is_effective():
    good = {"apiVersion": "velero.io/v1", "kind": "Restore", "metadata": {"name": "x"},
            "spec": {"backupName": "b", "existingResourcePolicy": "none"}}
    _validate(good)
    # (existingResourcePolicy is a free string in the v1.16.1 CRD; Velero checks "none"/"update" at runtime)
    for bad in ({**good, "spec": {**good["spec"], "restorePVs": "yes"}},
                {**good, "spec": {**good["spec"], "namespaceMap": {"a": "b"}}}):
        with pytest.raises(AssertionError):
            _validate(bad)
