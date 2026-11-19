"""IaC lifecycle manager: proposes teardown of expired ephemeral stacks.

Run on a schedule (Kubernetes CronJob / cron) with ``oplia-iac-lifecycle``.
For every expired, non-protected, consistently tagged stack it records an
``iac.destroy`` proposal in the safety gate. The proposal, once approved and
executed, dispatches the infrastructure pipeline with ``OPERATION=destroy``,
which itself runs ``terraform plan -destroy`` and waits for a second human
approval before applying. Nothing is destroyed by this worker directly.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.drivers.cicd.base import RemediationRequest
from oplia_ctl.lifecycle.sources import AwsTaggedSource, AzureTaggedSource, ResourceSource
from oplia_ctl.lifecycle.stacks import group_stacks, utcnow
from oplia_ctl.safety import ProposalStatus, SafetyGate

ACTION_IAC_DESTROY = "iac.destroy"
MAX_ATTEMPTS = 50
log = logging.getLogger("oplia.lifecycle")


@dataclass
class LifecycleReport:
    scanned_resources: int = 0
    stacks: int = 0
    not_expired: int = 0
    proposed: list[str] = field(default_factory=list)  # new proposal ids
    already_proposed: list[str] = field(default_factory=list)  # open/decided proposals, not duplicated
    skipped: list[tuple[str, str]] = field(default_factory=list)
    source_errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"scanned_resources": self.scanned_resources, "stacks": self.stacks,
                "not_expired": self.not_expired, "proposed": self.proposed,
                "already_proposed": self.already_proposed,
                "skipped": [{"target": t, "reason": r} for t, r in self.skipped],
                "source_errors": self.source_errors}


class IaCLifecycleManager:
    def __init__(
        self,
        *,
        gate: SafetyGate,
        sources: list[ResourceSource],
        target_cicd: Literal["github", "gitlab", "jenkins"],
        allowed_blueprints: list[str],
        clock: Callable[[], datetime] = utcnow,
        requested_by: str = "iac-lifecycle-manager",
    ) -> None:
        self._gate = gate
        self._sources = sources
        self._target = target_cicd
        self._allowed = set(allowed_blueprints)
        self._clock = clock
        self._requested_by = requested_by

    def run_once(self) -> LifecycleReport:
        report = LifecycleReport()
        resources = []
        for src in self._sources:
            try:
                resources.extend(src.list_resources())
            except Exception as exc:  # one failing cloud must not stop the others
                report.source_errors.append(f"{type(src).__name__}: {type(exc).__name__}: {str(exc)[:200]}")
        report.scanned_resources = len(resources)

        grouped = group_stacks(resources)
        report.skipped.extend(grouped.skipped)
        report.stacks = len(grouped.stacks)
        now = self._clock()

        for stack in grouped.stacks:
            if stack.cloud not in ("aws", "azure"):
                report.skipped.append((stack.key, f"cloud {stack.cloud!r} not supported by the destroy pipeline"))
                continue
            if stack.blueprint not in self._allowed:
                report.skipped.append((stack.key, f"blueprint {stack.blueprint!r} not in allowed list"))
                continue
            if not stack.is_expired(now):
                report.not_expired += 1
                continue
            digest = hashlib.sha256(f"{stack.key}|{stack.created_at.isoformat()}".encode()).hexdigest()
            try:
                req = RemediationRequest(zone_name=stack.zone, cloud=stack.cloud,  # type: ignore[arg-type]
                                         account_id=stack.account_id, blueprint=stack.blueprint,
                                         correlation_id=f"ttl-{digest[:24]}", operation="destroy")
            except ValidationError as exc:
                report.skipped.append((stack.key, f"tag values not safe for the pipeline: "
                                                  f"{exc.errors()[0]['msg']}"))
                continue
            # Attempt numbering: a new proposal is created only when every earlier attempt for
            # this stack incarnation EXPIRED (nobody decided) or FAILED (dispatch error).
            # A human REJECTED decision is respected; re-tagging the stack re-arms it.
            key_base = f"ttl:{digest[:40]}"
            key: str | None = None
            for attempt in range(1, MAX_ATTEMPTS + 1):
                candidate = f"{key_base}:{attempt}"
                existing = self._gate.find_by_idempotency_key(candidate)
                if existing is None:
                    key = candidate
                    break
                if existing.status in (ProposalStatus.EXPIRED, ProposalStatus.FAILED):
                    continue
                if existing.status is ProposalStatus.REJECTED:
                    report.skipped.append((stack.key, f"teardown rejected by {existing.decided_by}; "
                                                      "re-tag the stack to re-arm"))
                else:
                    report.already_proposed.append(existing.id)
                break
            else:
                report.skipped.append((stack.key, f"{MAX_ATTEMPTS} attempts expired or failed; "
                                                  "manual review required"))
            if key is None:
                continue
            overdue = now - stack.expires_at
            proposal = self._gate.propose(
                action_type=ACTION_IAC_DESTROY,
                target=stack.key,
                payload={"target_cicd": self._target, "request": req.model_dump(),
                         "resource_count": len(stack.resource_ids),
                         "resources_sample": list(stack.resource_ids[:20])},
                reason=(f"Ephemeral stack {stack.key} expired: created {stack.created_at.isoformat()}, "
                        f"TTL {stack.ttl}, overdue by {overdue - timedelta(microseconds=overdue.microseconds)}. "
                        f"{len(stack.resource_ids)} tagged resources."),
                requested_by=self._requested_by,
                idempotency_key=key,
            )
            report.proposed.append(proposal.id)
        return report


class LifecycleSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_LIFECYCLE_", extra="ignore")

    aws_regions: list[str] = Field(default_factory=list)
    azure_subscriptions: list[str] = Field(default_factory=list)
    target_cicd: Literal["github", "gitlab", "jenkins"] = "github"


def main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    from oplia_ctl.config import get_settings
    from oplia_ctl.db import Base, make_engine, make_session_factory

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    cfg = LifecycleSettings()
    sources: list[ResourceSource] = []
    if cfg.aws_regions:
        sources.append(AwsTaggedSource(cfg.aws_regions))
    if cfg.azure_subscriptions:
        sources.append(AzureTaggedSource(cfg.azure_subscriptions))
    if not sources:
        raise SystemExit("set OPLIA_LIFECYCLE_AWS_REGIONS and/or OPLIA_LIFECYCLE_AZURE_SUBSCRIPTIONS")
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    gate = SafetyGate(make_session_factory(engine), dry_run=settings.dry_run,
                      require_approval=settings.require_approval, four_eyes=settings.four_eyes,
                      proposal_ttl=timedelta(minutes=settings.proposal_ttl_minutes))
    report = IaCLifecycleManager(gate=gate, sources=sources, target_cicd=cfg.target_cicd,
                                 allowed_blueprints=settings.allowed_blueprints).run_once()
    print(json.dumps(report.as_dict(), indent=2))
    if report.source_errors:
        raise SystemExit(2)  # surface partial failure to the scheduler
