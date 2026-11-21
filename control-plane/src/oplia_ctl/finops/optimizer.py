"""Cost-optimisation policy engine: turns "Run Cleanup" advice into scheduled, gated actions.

Flow
----
1. ``observe`` (CronJob): detectors list idle resources - unattached AWS EBS volumes,
   unassociated Elastic IPs, unattached Azure managed disks, GCP disks without users. Each is
   recorded as a *candidate* with the time it was **first seen idle**; a candidate that is in
   use again is dropped (so the clock restarts).
2. A candidate idle for longer than the grace period (default 7 days) gets a ``finops.*``
   proposal in the safety gate - approval, four-eyes, kill switch and audit apply as usual.
3. ``run_window`` (CronJob during the maintenance window): executes the **approved** finops
   proposals. Executors refuse to run outside a maintenance window (the API answers 409 instead
   of changing the proposal state).

Every executor re-checks the live state just before acting (still unattached, not marked
``OpliaRetain``) and **snapshots disks before deleting them**, waiting for the snapshot to
complete; if the snapshot does not complete in time, nothing is deleted.

Never touched: resources tagged ``OpliaRetain`` (GCP label ``oplia-retain``) and resources whose
``Environment`` tag is a protected value (default prod / production / prd).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from typing import Annotated, Any, Literal, Protocol
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.db import session_scope
from oplia_ctl.finops.inventory import _aws_tags, _boto_client
from oplia_ctl.finops.models import OptimizationCandidateRow
from oplia_ctl.safety import ProposalStatus, SafetyGate

log = logging.getLogger("oplia.finops.optimizer")

ACTION_EBS_DELETE = "finops.aws.ebs_delete"
ACTION_EIP_RELEASE = "finops.aws.eip_release"
ACTION_AZURE_DISK_DELETE = "finops.azure.disk_delete"
ACTION_GCP_DISK_DELETE = "finops.gcp.disk_delete"
RETAIN_TAG = "OpliaRetain"
RETAIN_LABEL = "oplia-retain"
PROTECTED_ENVIRONMENTS = frozenset({"prod", "production", "prd"})
_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_OPEN = (ProposalStatus.PENDING, ProposalStatus.APPROVED, ProposalStatus.EXECUTING)


class FinOpsActionError(RuntimeError):
    """Live state no longer allows the action; nothing was changed."""


class MaintenanceWindowClosedError(RuntimeError):
    """The action may only run inside a maintenance window."""


# --------------------------------------------------------------------------- windows
class MaintenanceWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]] = Field(min_length=1)
    start: Annotated[str, Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")]
    end: Annotated[str, Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")]
    tz: str = "UTC"

    @field_validator("tz")
    @classmethod
    def _tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError(f"unknown time zone {v!r}") from None
        return v

    def contains(self, dt: datetime) -> bool:
        local = dt.astimezone(ZoneInfo(self.tz))
        start, end = time.fromisoformat(self.start), time.fromisoformat(self.end)
        day, t = _DAYS[local.weekday()], local.time()
        if start == end:
            return False
        if start < end:
            return day in self.days and start <= t < end
        prev = _DAYS[(local.weekday() - 1) % 7]  # window crosses midnight
        return (day in self.days and t >= start) or (prev in self.days and t < end)


class WindowGuard:
    def __init__(self, windows: list[MaintenanceWindow], clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self._windows = windows
        self._clock = clock

    def is_open(self) -> bool:
        now = self._clock()
        return any(w.contains(now) for w in self._windows)

    def require_open(self) -> None:
        if not self.is_open():
            raise MaintenanceWindowClosedError("outside every configured maintenance window")

    def describe(self) -> str:
        if not self._windows:
            return "no maintenance window configured (never runs)"
        return "; ".join(f"{','.join(w.days)} {w.start}-{w.end} {w.tz}" for w in self._windows)


def _protected(tags: dict[str, str], protected_envs: frozenset[str]) -> str | None:
    if RETAIN_TAG in tags or RETAIN_LABEL in tags:
        return f"marked {RETAIN_TAG}"
    env = tags.get("Environment") or tags.get("environment") or ""
    if env.strip().lower() in protected_envs:
        return f"Environment={env} is protected"
    return None


# ------------------------------------------------------------------------- detection
@dataclass(frozen=True)
class Candidate:
    cloud: str
    kind: str
    action_type: str
    resource_id: str
    payload: dict[str, Any]
    tags: dict[str, str] = field(default_factory=dict)
    size_hint: str | None = None


class IdleDetector(Protocol):
    name: str

    def candidates(self) -> Iterator[Candidate]: ...


class AwsIdleDetector:
    name = "aws"

    def __init__(self, regions: list[str], client_factory: Callable[[str, str | None], Any] = _boto_client):
        self._regions = regions
        self._client = client_factory

    def candidates(self) -> Iterator[Candidate]:
        for region in self._regions:
            ec2 = self._client("ec2", region)
            pages = ec2.get_paginator("describe_volumes").paginate(
                Filters=[{"Name": "status", "Values": ["available"]}])
            for page in pages:
                for v in page["Volumes"]:
                    yield Candidate("aws", "ebs_volume", ACTION_EBS_DELETE, f"{region}/{v['VolumeId']}",
                                    {"region": region, "volume_id": v["VolumeId"], "size_gb": v.get("Size"),
                                     "volume_type": v.get("VolumeType")},
                                    _aws_tags(v.get("Tags")), f"{v.get('Size')} GiB {v.get('VolumeType')}")
            for a in ec2.describe_addresses().get("Addresses", []):
                if a.get("AssociationId") or a.get("InstanceId") or a.get("NetworkInterfaceId"):
                    continue
                if not a.get("AllocationId"):
                    continue  # EC2-Classic style address without allocation id: not handled
                yield Candidate("aws", "elastic_ip", ACTION_EIP_RELEASE, f"{region}/{a['AllocationId']}",
                                {"region": region, "allocation_id": a["AllocationId"],
                                 "public_ip": a.get("PublicIp")}, _aws_tags(a.get("Tags")), "1 public IPv4")


def _azure_compute_client(subscription: str) -> Any:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient

    return ComputeManagementClient(DefaultAzureCredential(), subscription)


_RG_RE = re.compile(r"/resourceGroups/([^/]+)/", re.IGNORECASE)


def _enum_value(v: Any) -> str:
    return str(getattr(v, "value", v))


class AzureIdleDetector:
    name = "azure"

    def __init__(self, subscriptions: list[str], client_factory: Callable[[str], Any] = _azure_compute_client):
        self._subs = subscriptions
        self._client = client_factory

    def candidates(self) -> Iterator[Candidate]:
        for sub in self._subs:
            for d in self._client(sub).disks.list():
                if _enum_value(d.disk_state) != "Unattached" or d.managed_by:
                    continue
                m = _RG_RE.search(str(d.id))
                if m is None:
                    continue
                yield Candidate("azure", "azure_disk", ACTION_AZURE_DISK_DELETE, str(d.id),
                                {"subscription": sub, "resource_group": m.group(1), "name": str(d.name),
                                 "location": str(d.location), "size_gb": d.disk_size_gb},
                                dict(d.tags or {}), f"{d.disk_size_gb} GiB")


def _gcp_disks_client() -> Any:
    from google.cloud import compute_v1

    return compute_v1.DisksClient()


class GcpIdleDetector:
    name = "gcp"

    def __init__(self, projects: list[str], client_factory: Callable[[], Any] = _gcp_disks_client):
        self._projects = projects
        self._client = client_factory

    def candidates(self) -> Iterator[Candidate]:
        client = self._client()
        for project in self._projects:
            for _zone, scoped in client.aggregated_list(project=project):
                for d in getattr(scoped, "disks", None) or []:
                    if list(d.users or []):
                        continue
                    zone = str(d.zone).rsplit("/", 1)[-1]
                    yield Candidate("gcp", "gcp_disk", ACTION_GCP_DISK_DELETE, f"{project}/{zone}/{d.name}",
                                    {"project": project, "zone": zone, "name": str(d.name),
                                     "size_gb": int(d.size_gb or 0)},
                                    dict(d.labels or {}), f"{d.size_gb} GiB")


# -------------------------------------------------------------------------- optimizer
@dataclass
class ObserveReport:
    idle_seen: int = 0
    newly_idle: int = 0
    no_longer_idle: int = 0
    proposed: list[str] = field(default_factory=list)
    waiting_grace: int = 0
    already_proposed: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)
    detector_errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _aware(dt: datetime) -> datetime:
    # SQLite returns naive UTC, PostgreSQL returns the session time zone: always report UTC
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


class CostOptimizer:
    def __init__(
        self,
        *,
        gate: SafetyGate,
        session_factory: sessionmaker[Session],
        detectors: list[IdleDetector],
        grace: timedelta = timedelta(days=7),
        proposal_ttl: timedelta = timedelta(days=8),
        protected_environments: frozenset[str] = PROTECTED_ENVIRONMENTS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        requested_by: str = "finops-optimizer",
    ) -> None:
        self._gate = gate
        self._sf = session_factory
        self._detectors = detectors
        self._grace = grace
        self._proposal_ttl = proposal_ttl
        self._protected = protected_environments
        self._clock = clock
        self._requested_by = requested_by

    def observe(self) -> ObserveReport:
        now = self._clock()
        report = ObserveReport()
        clean_clouds: set[str] = set()
        found: dict[tuple[str, str], Candidate] = {}
        for det in self._detectors:
            try:
                items = list(det.candidates())
            except Exception as exc:
                report.detector_errors.append(f"{det.name}: {type(exc).__name__}: {str(exc)[:300]}")
                continue
            clean_clouds.add(det.name)
            for c in items:
                why = _protected(c.tags, self._protected)
                if why:
                    report.skipped.append((c.resource_id, why))
                    continue
                found[(c.cloud, c.resource_id)] = c
        report.idle_seen = len(found)

        due: list[tuple[Candidate, OptimizationCandidateRow]] = []
        with session_scope(self._sf) as s:
            existing = {(r.cloud, r.resource_id): r for r in s.execute(select(OptimizationCandidateRow)).scalars()}
            for key, row in existing.items():
                if key not in found and row.cloud in clean_clouds:
                    s.execute(delete(OptimizationCandidateRow).where(OptimizationCandidateRow.id == row.id))
                    report.no_longer_idle += 1
            for fkey, c in found.items():
                prior = existing.get(fkey)
                if prior is None:
                    row = OptimizationCandidateRow(
                        id=str(uuid.uuid4()), cloud=c.cloud, kind=c.kind, resource_id=c.resource_id,
                        payload_json=json.dumps(c.payload, sort_keys=True), monthly_cost_hint=c.size_hint,
                        first_seen_idle_at=now, last_seen_idle_at=now)
                    s.add(row)
                    report.newly_idle += 1
                else:
                    row = prior
                    row.last_seen_idle_at = now
                    row.payload_json = json.dumps(c.payload, sort_keys=True)
                if _aware(row.first_seen_idle_at) + self._grace <= now:
                    due.append((c, row))
                else:
                    report.waiting_grace += 1
            s.flush()
            due_info = [(c, r.id, _aware(r.first_seen_idle_at)) for c, r in due]

        for c, row_id, first_seen in due_info:
            base = "finops:" + hashlib.sha256(
                f"{c.cloud}|{c.resource_id}|{first_seen.isoformat()}".encode()).hexdigest()[:40]
            latest = self._gate.latest_by_idempotency_prefix(base + ":")
            attempt = 1
            if latest is not None:
                prev, prev_key = latest
                if prev.status in _OPEN or prev.status in (ProposalStatus.EXECUTED, ProposalStatus.DRY_RUN):
                    report.already_proposed += 1
                    continue
                if prev.status is ProposalStatus.REJECTED:
                    report.skipped.append((c.resource_id, f"cleanup rejected by {prev.decided_by}"))
                    continue
                attempt = int(prev_key.rsplit(":", 1)[1]) + 1  # EXPIRED or FAILED: try again
            idle_for = now - first_seen
            proposal = self._gate.propose(
                action_type=c.action_type, target=f"{c.cloud}/{c.resource_id}",
                payload={**c.payload, "kind": c.kind, "first_seen_idle_at": first_seen.isoformat()},
                reason=(f"{c.kind} {c.resource_id} ({c.size_hint or 'size unknown'}) idle since "
                        f"{first_seen.isoformat()} ({idle_for.days} days, grace {self._grace.days} days). "
                        "Executed only in a maintenance window; disks are snapshotted first."),
                requested_by=self._requested_by, idempotency_key=f"{base}:{attempt}", ttl=self._proposal_ttl)
            report.proposed.append(proposal.id)
            with session_scope(self._sf) as s:
                row_obj = s.get(OptimizationCandidateRow, row_id)
                if row_obj is not None:
                    row_obj.proposal_id = proposal.id
        return report

    def run_window(self, executors: dict[str, Any], guard: WindowGuard,
                   actor: str = "finops-maintenance-window") -> dict[str, Any]:
        if not guard.is_open():
            return {"window": "closed", "executed": []}
        statuses = [ProposalStatus.APPROVED, *([] if self._gate.require_approval else [ProposalStatus.PENDING])]
        results: list[dict[str, Any]] = []
        for st in statuses:
            for p in self._gate.list(st, limit=500):
                ex = executors.get(p.action_type)
                if ex is None or not p.action_type.startswith("finops."):
                    continue
                if self._gate.kill_switch_engaged():
                    return {"window": "open", "executed": results, "stopped": "kill switch engaged"}
                try:
                    done = self._gate.execute(p.id, ex, actor)
                    results.append({"proposal_id": p.id, "status": done.status.value})
                except Exception as exc:  # e.g. proposal expired meanwhile; continue with the rest
                    results.append({"proposal_id": p.id, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
        return {"window": "open", "executed": results}


def list_candidates(sf: sessionmaker[Session], limit: int = 200) -> list[dict[str, Any]]:
    with session_scope(sf) as s:
        rows = s.execute(select(OptimizationCandidateRow).order_by(OptimizationCandidateRow.first_seen_idle_at)
                         .limit(max(1, min(limit, 1000)))).scalars()
        return [{"id": r.id, "cloud": r.cloud, "kind": r.kind, "resource_id": r.resource_id,
                 "size": r.monthly_cost_hint, "first_seen_idle_at": _aware(r.first_seen_idle_at).isoformat(),
                 "last_seen_idle_at": _aware(r.last_seen_idle_at).isoformat(), "proposal_id": r.proposal_id}
                for r in rows]


# ------------------------------------------------------------------------- executors
_VOL_RE = re.compile(r"^vol-[0-9a-f]{8,17}$")
_EIP_RE = re.compile(r"^eipalloc-[0-9a-f]{8,17}$")
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_AZ_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_AZ_RG_RE = re.compile(r"^[-\w._()]{1,90}$")
_GCP_NAME_RE = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")
_GCP_PROJECT_RE = re.compile(r"^[a-z][-a-z0-9]{4,28}[a-z0-9]$")
_GCP_ZONE_RE = re.compile(r"^[a-z]+-[a-z]+\d+-[a-z]$")
_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


def _req(payload: dict[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    v = str(payload.get(key, ""))
    if not pattern.fullmatch(v):
        raise ValueError(f"invalid {key} {v!r}")
    return v


class _WindowedExecutor:
    def __init__(self, guard: WindowGuard, protected_environments: frozenset[str] = PROTECTED_ENVIRONMENTS):
        self._guard = guard
        self._protected = protected_environments

    def check_ready(self, payload: dict[str, Any]) -> None:
        """Called by the API before execution: outside a window it refuses without a state change."""
        self.describe(payload)
        self._guard.require_open()

    def describe(self, payload: dict[str, Any]) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def _check_live_tags(self, tags: dict[str, str]) -> None:
        why = _protected(tags, self._protected)
        if why:
            raise FinOpsActionError(f"resource is now {why}; not changed")


class AwsEbsDeleteExecutor(_WindowedExecutor):
    def __init__(self, guard: WindowGuard, *, client_factory: Callable[[str, str | None], Any] = _boto_client,
                 snapshot_wait_seconds: int = 1800, poll_seconds: int = 15, **kw: Any) -> None:
        super().__init__(guard, **kw)
        self._client = client_factory
        self._attempts = max(1, snapshot_wait_seconds // max(1, poll_seconds))
        self._poll = poll_seconds

    def describe(self, payload: dict[str, Any]) -> str:
        vid = _req(payload, "volume_id", _VOL_RE)
        region = _req(payload, "region", _REGION_RE)
        return (f"Snapshot EBS volume {vid} in {region}, wait for completion, then delete the volume "
                f"(only if still unattached; maintenance window: {self._guard.describe()})")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        from botocore.exceptions import ClientError, WaiterError

        self.describe(payload)
        self._guard.require_open()
        vid, region = payload["volume_id"], payload["region"]
        ec2 = self._client("ec2", region)

        def live() -> dict[str, Any]:
            try:
                vols = ec2.describe_volumes(VolumeIds=[vid])["Volumes"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVolume.NotFound":
                    raise FinOpsActionError(f"volume {vid} no longer exists") from None
                raise
            v: dict[str, Any] = vols[0]
            if v["State"] != "available" or v.get("Attachments"):
                raise FinOpsActionError(f"volume {vid} is {v['State']} / attached now; not deleted")
            self._check_live_tags(_aws_tags(v.get("Tags")))
            return v

        vol = live()
        keep = [t for t in vol.get("Tags", []) if not t["Key"].startswith("aws:")][:40]
        snap = ec2.create_snapshot(
            VolumeId=vid, Description=f"OPLIA pre-delete backup of {vid}",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                *keep,
                {"Key": "OpliaSourceVolume", "Value": vid},
                {"Key": "OpliaReason", "Value": "finops-unattached-volume-cleanup"}]}])
        sid = snap["SnapshotId"]
        try:
            ec2.get_waiter("snapshot_completed").wait(
                SnapshotIds=[sid], WaiterConfig={"Delay": self._poll, "MaxAttempts": self._attempts})
        except WaiterError as exc:
            raise FinOpsActionError(f"snapshot {sid} did not complete ({exc}); volume {vid} NOT deleted") from None
        live()  # re-check: someone may have attached it while the snapshot ran
        ec2.delete_volume(VolumeId=vid)
        return {"deleted_volume": vid, "region": region, "snapshot_id": sid,
                "restore": f"aws ec2 create-volume --snapshot-id {sid} --availability-zone "
                           f"{vol.get('AvailabilityZone')} --volume-type {vol.get('VolumeType')}"}


class AwsEipReleaseExecutor(_WindowedExecutor):
    def __init__(self, guard: WindowGuard, *, client_factory: Callable[[str, str | None], Any] = _boto_client,
                 **kw: Any) -> None:
        super().__init__(guard, **kw)
        self._client = client_factory

    def describe(self, payload: dict[str, Any]) -> str:
        aid = _req(payload, "allocation_id", _EIP_RE)
        region = _req(payload, "region", _REGION_RE)
        return (f"Release Elastic IP {aid} ({payload.get('public_ip')}) in {region} if still unassociated "
                f"(the address cannot be recovered afterwards; window: {self._guard.describe()})")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.describe(payload)
        self._guard.require_open()
        aid, region = payload["allocation_id"], payload["region"]
        ec2 = self._client("ec2", region)
        addrs = ec2.describe_addresses(AllocationIds=[aid]).get("Addresses", [])
        if not addrs:
            raise FinOpsActionError(f"Elastic IP {aid} no longer exists")
        a = addrs[0]
        if a.get("AssociationId") or a.get("InstanceId") or a.get("NetworkInterfaceId"):
            raise FinOpsActionError(f"Elastic IP {aid} is associated now; not released")
        self._check_live_tags(_aws_tags(a.get("Tags")))
        ec2.release_address(AllocationId=aid)
        return {"released": aid, "public_ip": a.get("PublicIp"), "region": region}


class AzureDiskDeleteExecutor(_WindowedExecutor):
    def __init__(self, guard: WindowGuard, *, client_factory: Callable[[str], Any] = _azure_compute_client,
                 lro_timeout_seconds: int = 1800, clock: Callable[[], datetime] = lambda: datetime.now(UTC),
                 **kw: Any) -> None:
        super().__init__(guard, **kw)
        self._client = client_factory
        self._timeout = lro_timeout_seconds
        self._clock = clock

    def describe(self, payload: dict[str, Any]) -> str:
        sub = _req(payload, "subscription", _UUID_RE)
        rg = _req(payload, "resource_group", _AZ_RG_RE)
        name = _req(payload, "name", _AZ_NAME_RE)
        return (f"Snapshot (incremental) Azure disk {rg}/{name} in subscription {sub}, then delete it if still "
                f"unattached (window: {self._guard.describe()})")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        from azure.mgmt.compute.models import CreationData, Snapshot, SnapshotProperties

        self.describe(payload)
        self._guard.require_open()
        sub, rg, name = payload["subscription"], payload["resource_group"], payload["name"]
        compute = self._client(sub)

        def live() -> Any:
            d = compute.disks.get(rg, name)
            if _enum_value(d.disk_state) != "Unattached" or d.managed_by:
                raise FinOpsActionError(f"disk {rg}/{name} is {_enum_value(d.disk_state)} now; not deleted")
            self._check_live_tags(dict(d.tags or {}))
            return d

        disk = live()
        snap_name = f"oplia-{name}"[:60] + "-" + self._clock().strftime("%Y%m%d%H%M")
        snapshot = Snapshot(
            location=disk.location,
            properties=SnapshotProperties(
                creation_data=CreationData(create_option="Copy", source_resource_id=disk.id), incremental=True),
            tags={**dict(disk.tags or {}), "OpliaSourceDisk": name, "OpliaReason": "finops-unattached-disk-cleanup"})
        created = compute.snapshots.begin_create_or_update(rg, snap_name, snapshot).result(timeout=self._timeout)
        state = _enum_value(getattr(created, "provisioning_state", "Succeeded"))
        if state != "Succeeded":
            raise FinOpsActionError(f"snapshot {snap_name} is {state}; disk {name} NOT deleted")
        live()
        compute.disks.begin_delete(rg, name).result(timeout=self._timeout)
        return {"deleted_disk": f"{rg}/{name}", "snapshot": f"{rg}/{snap_name}", "subscription": sub}


class GcpDiskDeleteExecutor(_WindowedExecutor):
    def __init__(self, guard: WindowGuard, *, client_factory: Callable[[], Any] = _gcp_disks_client,
                 op_timeout_seconds: int = 1800, clock: Callable[[], datetime] = lambda: datetime.now(UTC),
                 **kw: Any) -> None:
        super().__init__(guard, **kw)
        self._client = client_factory
        self._timeout = op_timeout_seconds
        self._clock = clock

    def describe(self, payload: dict[str, Any]) -> str:
        project = _req(payload, "project", _GCP_PROJECT_RE)
        zone = _req(payload, "zone", _GCP_ZONE_RE)
        name = _req(payload, "name", _GCP_NAME_RE)
        return (f"Snapshot GCP disk {project}/{zone}/{name}, then delete it if it still has no users "
                f"(window: {self._guard.describe()})")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        from google.cloud import compute_v1

        self.describe(payload)
        self._guard.require_open()
        project, zone, name = payload["project"], payload["zone"], payload["name"]
        client = self._client()

        def live() -> Any:
            d = client.get(project=project, zone=zone, disk=name)
            if list(d.users or []):
                raise FinOpsActionError(f"disk {name} is in use by {list(d.users)}; not deleted")
            self._check_live_tags(dict(d.labels or {}))
            return d

        disk = live()
        snap_name = (f"oplia-{name}"[:48].rstrip("-") + "-" + self._clock().strftime("%Y%m%d%H%M"))
        labels = {**dict(disk.labels or {}), "oplia-source-disk": name[:63], "oplia-reason": "finops-cleanup"}
        op = client.create_snapshot(project=project, zone=zone, disk=name,
                                    snapshot_resource=compute_v1.Snapshot(name=snap_name, labels=labels))
        op.result(timeout=self._timeout)  # raises on error or timeout -> disk not deleted
        live()
        client.delete(project=project, zone=zone, disk=name).result(timeout=self._timeout)
        return {"deleted_disk": f"{project}/{zone}/{name}", "snapshot": f"{project}/global/snapshots/{snap_name}"}
