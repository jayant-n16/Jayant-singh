"""AIOps self-healing engine (the document's ``aiops_remediation_engine``).

``POST /webhooks/aiops/alert`` -> :meth:`AIOpsEngine.handle`:

1. validate the alert and check it belongs to the cluster this control plane manages;
2. evaluate the matrix (first matching rule wins);
3. record a proposal for the mapped action in the safety gate (or nothing for
   ``notify_only`` / no match);
4. send the incident to PagerDuty and Slack (``opened``).

When the proposal is executed, :class:`NotifyBeforeActExecutor` notifies again
(``pre_action``) *before* the Kubernetes change or runbook Job, and reports the result.

De-duplication: one proposal per (workload, rule) at a time. While one is open, repeats are
reported as ``already_proposed`` and do not page again; after it reaches a final state a new
one is allowed only once the cool-down has passed since that decision or execution.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from oplia_ctl.aiops.executors import (
    ACTION_HPA_SCALE,
    ACTION_ROLLING_RESTART,
    ACTION_RUNBOOK,
    job_suffix,
    validate_namespace,
)
from oplia_ctl.aiops.matrix import Alert, Rule, evaluate
from oplia_ctl.aiops.notify import Incident, IncidentNotifier
from oplia_ctl.aiops.runbooks import RunbookSpec
from oplia_ctl.safety import ProposalStatus, SafetyGate

log = logging.getLogger("oplia.aiops")

ACTION_TYPES: dict[str, str] = {
    "k8s.hpa_scale": ACTION_HPA_SCALE,
    "k8s.rolling_restart": ACTION_ROLLING_RESTART,
    "runbook": ACTION_RUNBOOK,
}
_OPEN = (ProposalStatus.PENDING, ProposalStatus.APPROVED, ProposalStatus.EXECUTING)


class AlertRejectedError(ValueError):
    """The alert is well-formed but must not be acted on by this control plane."""


class AIOpsEngine:
    def __init__(
        self,
        *,
        gate: SafetyGate,
        notifier: IncidentNotifier,
        rules: list[Rule],
        runbooks: dict[str, RunbookSpec],
        cluster_name: str,
        cooldown: timedelta = timedelta(minutes=30),
        public_base_url: str = "",
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        requested_by: str = "aiops-engine",
    ) -> None:
        if not cluster_name:
            raise ValueError("cluster_name is required")
        missing = sorted({r.runbook for r in rules if r.runbook and r.runbook not in runbooks})
        if missing:
            raise ValueError(f"matrix references unregistered runbooks: {missing}")
        if public_base_url and not public_base_url.startswith("https://"):
            raise ValueError("public_base_url must use https")
        self._gate = gate
        self._notifier = notifier
        self._rules = rules
        self._runbooks = runbooks
        self._cluster = cluster_name
        self._cooldown = cooldown
        self._base = public_base_url.rstrip("/")
        self._clock = clock
        self._requested_by = requested_by

    # ----------------------------------------------------------------- helpers
    def _incident(self, alert: Alert, rule: Rule | None, proposal_id: str | None) -> Incident:
        w = alert.workload
        workload = f"{w.kind}/{w.namespace}/{w.name}"
        rule_name = rule.name if rule else "unmatched"
        dedup = "oplia-aiops-" + hashlib.sha256(
            f"{alert.cluster}|{workload}|{rule_name if rule else alert.metric}".encode()).hexdigest()[:32]
        details: dict[str, Any] = {
            "cluster": alert.cluster, "workload": workload, "metric": alert.metric,
            "value": alert.value, "observed_at": alert.observed_at.isoformat(),
            "alert_id": alert.alert_id, "alert_source": alert.source, "rule": rule_name,
        }
        if alert.correlated:
            details["correlated"] = ", ".join(f"{k}={v:g}" for k, v in sorted(alert.correlated.items()))
        if rule:
            details["rca"] = f"{rule.explain()} -> {rule.action}" + (f" ({rule.runbook})" if rule.runbook else "")
        if proposal_id:
            details["proposal_id"] = proposal_id
        links: tuple[tuple[str, str], ...] = ()
        if proposal_id and self._base:
            links = ((f"{self._base}/proposals/{proposal_id}", "Review proposal"),)
        what = rule.description if rule else f"{alert.metric}={alert.value:g} (no matching rule)"
        return Incident(
            dedup_key=dedup,
            summary=f"{workload} on {alert.cluster}: {what}"[:900],
            severity=rule.severity if rule else "warning",
            source=f"{alert.cluster}/{w.namespace}",
            klass=alert.metric, component=f"{w.kind}/{w.name}", group=w.namespace,
            details=details, links=links,
        )

    def _next_key(self, base: str) -> tuple[str | None, dict[str, Any] | None]:
        """Return (new idempotency key, None) or (None, reason-if-suppressed)."""
        latest = self._gate.latest_by_idempotency_prefix(base + ":")
        if latest is None:
            return f"{base}:1", None
        prev, key = latest
        if prev.status in _OPEN:
            return None, {"outcome": "already_proposed", "proposal_id": prev.id, "status": prev.status.value}
        decided = prev.executed_at or prev.decided_at or prev.expires_at
        if decided + self._cooldown > self._clock():
            return None, {"outcome": "cooldown", "proposal_id": prev.id, "status": prev.status.value,
                          "until": (decided + self._cooldown).isoformat()}
        return f"{base}:{int(key.rsplit(':', 1)[1]) + 1}", None

    # ------------------------------------------------------------------- entry
    def handle(self, alert: Alert) -> dict[str, Any]:
        if alert.cluster != self._cluster:
            raise AlertRejectedError(f"alert is for cluster {alert.cluster!r}; this control plane manages "
                                     f"{self._cluster!r}")
        try:
            validate_namespace(alert.workload.namespace)
        except ValueError as exc:
            raise AlertRejectedError(str(exc)) from None

        rule = evaluate(self._rules, alert)
        base_result: dict[str, Any] = {"alert_id": alert.alert_id, "rule": rule.name if rule else None,
                                       "action": rule.action if rule else None}
        if rule is None or rule.action == "notify_only":
            sent = self._notifier.notify(self._incident(alert, rule, None), "opened")
            return {**base_result, "outcome": "notified_only", "notifications": sent}

        w = alert.workload
        if rule.action == "runbook" and rule.runbook is not None:
            spec = self._runbooks[rule.runbook]
            if w.namespace not in spec.allowed_namespaces:
                sent = self._notifier.notify(self._incident(alert, rule, None), "opened")
                return {**base_result, "outcome": "notified_only", "notifications": sent,
                        "reason": f"runbook {rule.runbook!r} is not allowed in namespace {w.namespace!r}"}

        base = "aiops:" + hashlib.sha256(
            f"{alert.cluster}|{w.namespace}|{w.kind}|{w.name}|{rule.name}".encode()).hexdigest()[:40]
        key, suppressed = self._next_key(base)
        if key is None:
            return {**base_result, **(suppressed or {})}

        payload: dict[str, Any] = {"namespace": w.namespace, "kind": w.kind, "name": w.name,
                                   "alert_id": alert.alert_id}
        if rule.action == "k8s.hpa_scale":
            payload["hpa"] = w.hpa
        if rule.action == "runbook":
            payload.update(runbook=rule.runbook, database=w.database, job_suffix=job_suffix(key))
        incident = self._incident(alert, rule, None)
        payload["incident"] = {
            "dedup_key": incident.dedup_key, "summary": incident.summary, "severity": incident.severity,
            "source": incident.source, "klass": incident.klass, "component": incident.component,
            "group": incident.group, "details": incident.details,
        }
        proposal = self._gate.propose(
            action_type=ACTION_TYPES[rule.action],
            target=f"{alert.cluster}/{w.kind}/{w.namespace}/{w.name}",
            payload=payload,
            reason=(f"AIOps rule '{rule.name}': {rule.explain()} observed "
                    f"({alert.metric}={alert.value:g} at {alert.observed_at.isoformat()}, source {alert.source}). "
                    f"{rule.description}."),
            requested_by=self._requested_by,
            idempotency_key=key,
        )
        if proposal.payload.get("alert_id") != alert.alert_id:
            # a concurrent alert for the same workload and rule created this proposal first
            return {**base_result, "outcome": "already_proposed", "proposal_id": proposal.id,
                    "status": proposal.status.value}
        sent = self._notifier.notify(self._incident(alert, rule, proposal.id), "opened")
        return {**base_result, "outcome": "proposed", "proposal_id": proposal.id,
                "status": proposal.status.value, "notifications": sent}
