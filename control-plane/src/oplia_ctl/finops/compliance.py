"""Tag compliance: policy, evaluation, and the scanner that maintains the compliance log.

Required tags default to the document's exact, case-sensitive ``Owner``, ``CostCenter`` and
``Environment``. Per cloud, a required tag may also be satisfied by a mapped key - needed on GCP,
where label keys must be lowercase (default mapping ``owner`` / ``costcenter`` / ``environment``);
on GCP a Resource Manager tag with the exact short name satisfies the requirement too.

For each resource the result separates:

* ``missing``    - no key at all
* ``wrong_case`` - only a key differing in case (e.g. ``owner`` on AWS) - not compliant
* ``invalid``    - key present but the value is empty, or Environment is not an allowed value

The scanner upserts one finding per non-compliant resource (``OPEN``), resolves findings whose
resource became compliant or no longer exists (only for scopes that were scanned without error),
and sends **one** digest per scan to the operations desk when there are new findings.
It never changes anything in the clouds.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.aiops.notify import Incident, IncidentNotifier
from oplia_ctl.db import session_scope
from oplia_ctl.finops.inventory import InventorySource, Resource
from oplia_ctl.finops.models import ComplianceFindingRow, ComplianceScanRow

log = logging.getLogger("oplia.finops")

TagKey = Annotated[str, Field(min_length=1, max_length=128)]


class TagPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    required: list[TagKey] = Field(default_factory=lambda: ["Owner", "CostCenter", "Environment"], min_length=1)
    # per cloud: required key -> alternative key accepted on that cloud
    key_aliases: dict[str, dict[str, TagKey]] = Field(default_factory=lambda: {
        "gcp": {"Owner": "owner", "CostCenter": "costcenter", "Environment": "environment"}})
    allowed_environments: list[str] | None = None  # e.g. ["dev", "stg", "prod"]; None = any non-empty
    environment_key: str = "Environment"


@dataclass(frozen=True)
class Evaluation:
    resource: Resource
    missing: list[str] = field(default_factory=list)
    wrong_case: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return not (self.missing or self.wrong_case or self.invalid)


def evaluate(policy: TagPolicy, r: Resource) -> Evaluation:
    aliases = policy.key_aliases.get(r.cloud, {})
    merged = {**r.labels, **r.tags}  # exact tags win over labels with the same key
    lower = {k.lower(): k for k in merged}
    missing: list[str] = []
    wrong_case: list[str] = []
    invalid: list[str] = []
    for key in policy.required:
        candidates = [key] + ([aliases[key]] if key in aliases else [])
        found = next((c for c in candidates if c in merged), None)
        if found is None:
            near = next((lower[c.lower()] for c in candidates if c.lower() in lower), None)
            if near is not None:
                wrong_case.append(f"{key} (found '{near}')")
            else:
                missing.append(key)
            continue
        value = merged[found].strip()
        if not value:
            invalid.append(f"{key}: empty value")
        elif (key == policy.environment_key and policy.allowed_environments is not None
              and value not in policy.allowed_environments):
            invalid.append(f"{key}: '{value}' not in {policy.allowed_environments}")
    return Evaluation(r, missing, wrong_case, invalid)


@dataclass
class ScanReport:
    scan_id: str
    resources_scanned: int = 0
    noncompliant: int = 0
    new_findings: int = 0
    updated_findings: int = 0
    resolved_findings: int = 0
    by_cloud: dict[str, dict[str, int]] = field(default_factory=dict)
    source_errors: list[str] = field(default_factory=list)
    alert: dict[str, str] | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class ComplianceScanner:
    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session] | None,
        sources: list[InventorySource],
        policy: TagPolicy | None = None,
        notifier: IncidentNotifier | None = None,
        alert_channels: list[str] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sample_size: int = 15,
    ) -> None:
        self._sf = session_factory
        self._sources = sources
        self._policy = policy or TagPolicy()
        self._notifier = notifier
        self._channels = alert_channels
        self._clock = clock
        self._sample = sample_size

    def evaluate_all(self, report: ScanReport) -> tuple[list[Evaluation], set[tuple[str, str]]]:
        """Inventory + evaluation. Returns evaluations and the (cloud, scope) pairs scanned cleanly."""
        evaluations: list[Evaluation] = []
        clean: set[tuple[str, str]] = set()
        for src in self._sources:
            try:
                scopes = src.scopes()
                items = list(src.list_resources())
            except Exception as exc:  # one failing cloud must not stop the others
                report.source_errors.append(f"{src.name}: {type(exc).__name__}: {str(exc)[:300]}")
                log.warning("inventory source %s failed: %s", src.name, exc)
                continue
            clean.update((src.name, s) for s in scopes)
            for r in items:
                ev = evaluate(self._policy, r)
                evaluations.append(ev)
                stats = report.by_cloud.setdefault(r.cloud, {"scanned": 0, "noncompliant": 0})
                stats["scanned"] += 1
                if not ev.compliant:
                    stats["noncompliant"] += 1
        report.resources_scanned = len(evaluations)
        report.noncompliant = sum(1 for e in evaluations if not e.compliant)
        return evaluations, clean

    def audit(self) -> tuple[ScanReport, list[Evaluation]]:
        """Read-only audit: nothing is written and no alert is sent."""
        report = ScanReport(scan_id="audit-only")
        evaluations, _ = self.evaluate_all(report)
        return report, [e for e in evaluations if not e.compliant]

    def run(self) -> ScanReport:
        if self._sf is None:
            raise RuntimeError("run() needs a database; use audit() for a read-only scan")
        now = self._clock()
        report = ScanReport(scan_id=str(uuid.uuid4()))
        with session_scope(self._sf) as s:
            s.add(ComplianceScanRow(id=report.scan_id, started_at=now, resources_scanned=0, noncompliant=0,
                                    new_findings=0, resolved_findings=0, source_errors_json="[]"))
        evaluations, clean = self.evaluate_all(report)
        new_rows: list[Evaluation] = []
        seen: set[tuple[str, str]] = set()
        with session_scope(self._sf) as s:
            for ev in evaluations:
                r = ev.resource
                seen.add((r.cloud, r.resource_id))
                row = s.execute(select(ComplianceFindingRow).where(
                    ComplianceFindingRow.cloud == r.cloud,
                    ComplianceFindingRow.resource_id == r.resource_id)).scalar_one_or_none()
                if ev.compliant:
                    if row is not None and row.status == "OPEN":
                        row.status, row.resolved_at, row.resolution = "RESOLVED", now, "tagged"
                        row.last_seen_at, row.last_scan_id = now, report.scan_id
                        report.resolved_findings += 1
                    continue
                fields = {
                    "scope": r.scope[:256], "region": r.region[:64], "category": r.category,
                    "resource_type": r.resource_type[:128], "name": r.name[:512],
                    "missing_json": json.dumps(ev.missing), "wrong_case_json": json.dumps(ev.wrong_case),
                    "invalid_json": json.dumps(ev.invalid),
                    "owner_hint": (r.tags.get("Owner") or r.labels.get("owner") or None),
                    "last_seen_at": now, "last_scan_id": report.scan_id,
                }
                if row is None:
                    s.add(ComplianceFindingRow(id=str(uuid.uuid4()), cloud=r.cloud, resource_id=r.resource_id,
                                               status="OPEN", first_seen_at=now, **fields))
                    report.new_findings += 1
                    new_rows.append(ev)
                else:
                    reopened = row.status != "OPEN"
                    for k, v in fields.items():
                        setattr(row, k, v)
                    if reopened:
                        row.status, row.resolved_at, row.resolution = "OPEN", None, None
                        report.new_findings += 1
                        new_rows.append(ev)
                    else:
                        report.updated_findings += 1
            # resources gone from a cleanly scanned scope: the finding is closed as "not found"
            for row in s.execute(select(ComplianceFindingRow).where(ComplianceFindingRow.status == "OPEN")).scalars():
                if (row.cloud, row.resource_id) not in seen and (row.cloud, row.scope) in clean:
                    row.status, row.resolved_at, row.resolution = "RESOLVED", now, "resource not found"
                    row.last_scan_id = report.scan_id
                    report.resolved_findings += 1
        if new_rows and self._notifier is not None:
            report.alert = self._notifier.notify(self._digest(report, new_rows), "opened", only=self._channels)
        with session_scope(self._sf) as s:
            s.execute(update(ComplianceScanRow).where(ComplianceScanRow.id == report.scan_id).values(
                finished_at=self._clock(), resources_scanned=report.resources_scanned,
                noncompliant=report.noncompliant, new_findings=report.new_findings,
                resolved_findings=report.resolved_findings,
                source_errors_json=json.dumps(report.source_errors),
                alert_json=json.dumps(report.alert) if report.alert is not None else None))
        return report

    def _digest(self, report: ScanReport, new_rows: list[Evaluation]) -> Incident:
        details: dict[str, Any] = {
            "scan_id": report.scan_id, "scanned": report.resources_scanned,
            "noncompliant_total": report.noncompliant, "new": report.new_findings,
            "required_tags": ", ".join(self._policy.required),
        }
        for i, ev in enumerate(new_rows[: self._sample], 1):
            problems = ev.missing + ev.wrong_case + ev.invalid
            details[f"{i:02d}"] = (f"{ev.resource.cloud} {ev.resource.resource_type} {ev.resource.name} "
                                   f"({ev.resource.scope}): {'; '.join(problems)}")
        if len(new_rows) > self._sample:
            details["more"] = f"{len(new_rows) - self._sample} more in the compliance log"
        return Incident(
            dedup_key=f"oplia-finops-scan-{report.scan_id}",
            summary=f"Tag compliance: {report.new_findings} new non-compliant resources "
                    f"({report.noncompliant} open of {report.resources_scanned} scanned)",
            severity="warning", source="oplia-finops-scanner", klass="tag-compliance",
            component="finops", group="finops", details=details)


def list_findings(sf: sessionmaker[Session], *, status: str | None = None, cloud: str | None = None,
                  limit: int = 100) -> list[dict[str, Any]]:
    with session_scope(sf) as s:
        q = select(ComplianceFindingRow).order_by(ComplianceFindingRow.last_seen_at.desc()).limit(
            max(1, min(limit, 1000)))
        if status:
            q = q.where(ComplianceFindingRow.status == status)
        if cloud:
            q = q.where(ComplianceFindingRow.cloud == cloud)
        return [{
            "id": r.id, "cloud": r.cloud, "scope": r.scope, "region": r.region, "category": r.category,
            "resource_type": r.resource_type, "resource_id": r.resource_id, "name": r.name,
            "missing": json.loads(r.missing_json), "wrong_case": json.loads(r.wrong_case_json),
            "invalid": json.loads(r.invalid_json), "owner_hint": r.owner_hint, "status": r.status,
            "first_seen_at": _aware(r.first_seen_at).isoformat(), "last_seen_at": _aware(r.last_seen_at).isoformat(),
            "resolved_at": _aware(r.resolved_at).isoformat() if r.resolved_at else None, "resolution": r.resolution,
        } for r in s.execute(q).scalars()]


def list_scans(sf: sessionmaker[Session], limit: int = 20) -> list[dict[str, Any]]:
    with session_scope(sf) as s:
        rows = s.execute(select(ComplianceScanRow).order_by(ComplianceScanRow.started_at.desc())
                         .limit(max(1, min(limit, 200)))).scalars()
        return [{
            "id": r.id, "started_at": _aware(r.started_at).isoformat(),
            "finished_at": _aware(r.finished_at).isoformat() if r.finished_at else None,
            "resources_scanned": r.resources_scanned, "noncompliant": r.noncompliant,
            "new_findings": r.new_findings, "resolved_findings": r.resolved_findings,
            "source_errors": json.loads(r.source_errors_json),
            "alert": json.loads(r.alert_json) if r.alert_json else None,
        } for r in rows]
