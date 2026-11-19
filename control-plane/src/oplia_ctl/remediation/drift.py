"""Drift auto-remediation.

A drift detector posts a signed event. The control plane validates it, records a
``drift.remediate`` proposal (deduplicated by delivery id), and once approved the
executor dispatches the configured CI/CD pipeline. The pipeline itself still
runs ``terraform plan`` and pauses for a protected-environment approval before
``apply`` (see ``pipelines/``), so a single compromised component cannot change
infrastructure on its own.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from oplia_ctl.drivers.cicd.base import CICDDriver, Cloud, RemediationRequest
from oplia_ctl.safety import Proposal, SafetyGate

ACTION_DRIFT_REMEDIATE = "drift.remediate"


class DriftEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    zone_name: str
    cloud: Cloud
    account_id: str
    blueprint: str
    target_cicd: Literal["github", "gitlab", "jenkins"]
    detail: str = ""


class BlueprintNotAllowedError(ValueError):
    pass


def propose_drift_remediation(
    gate: SafetyGate,
    event: DriftEvent,
    *,
    delivery_id: str,
    allowed_blueprints: list[str],
    requested_by: str = "drift-detector",
) -> Proposal:
    if event.blueprint not in allowed_blueprints:
        raise BlueprintNotAllowedError(f"blueprint {event.blueprint!r} is not in the allowed list")
    req = RemediationRequest(
        zone_name=event.zone_name,
        cloud=event.cloud,
        account_id=event.account_id,
        blueprint=event.blueprint,
        correlation_id=delivery_id,
    )  # validates every field against strict patterns
    return gate.propose(
        action_type=ACTION_DRIFT_REMEDIATE,
        target=f"{event.cloud}:{event.account_id}:{event.zone_name}",
        payload={"target_cicd": event.target_cicd, "request": req.model_dump()},
        reason=f"drift detected in zone {event.zone_name} (blueprint {event.blueprint}). {event.detail}"[:2000],
        requested_by=requested_by,
        idempotency_key=f"drift:{delivery_id}",
    )


class DriftRemediationExecutor:
    def __init__(self, driver_for: Callable[[str], CICDDriver]) -> None:
        self._driver_for = driver_for

    def _parse(self, payload: dict[str, Any]) -> tuple[CICDDriver, RemediationRequest]:
        return self._driver_for(str(payload["target_cicd"])), RemediationRequest(**payload["request"])

    def describe(self, payload: dict[str, Any]) -> str:
        driver, req = self._parse(payload)
        return driver.describe(req)

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        driver, req = self._parse(payload)
        res = driver.trigger(req)
        return {"system": res.system, "accepted": res.accepted, "reference": res.reference, **res.detail}
