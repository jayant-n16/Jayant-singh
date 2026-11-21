"""Runtime threat events: normalisation and confidence scoring.

Input is Falco JSON output (directly, or via falcosidekick). Falco has no native
confidence score, so confidence is taken from, in order:

1. a numeric ``confidence`` field in [0, 1] on the event (set by an upstream
   detector or enrichment step), else
2. a fixed mapping from Falco ``priority`` (documented below).

The isolation target comes from an explicit ``oplia_target`` object added by
enrichment (AWS instance or Azure NIC), else from the Kubernetes namespace in
``output_fields``. Events with no resolvable target are exported to the SIEM but
never produce an isolation proposal.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

PRIORITY_CONFIDENCE: dict[str, float] = {
    "emergency": 1.0,
    "alert": 0.95,
    "critical": 0.9,
    "error": 0.8,
    "warning": 0.6,
    "notice": 0.4,
    "informational": 0.2,
    "info": 0.2,
    "debug": 0.1,
}


@dataclass(frozen=True)
class IsolationTarget:
    kind: str  # "aws" | "azure" | "k8s"
    params: dict[str, str]

    @property
    def action_type(self) -> str:
        return f"isolate.{self.kind}"

    @property
    def label(self) -> str:
        return f"{self.kind}:" + ",".join(f"{k}={v}" for k, v in sorted(self.params.items()))


@dataclass(frozen=True)
class ThreatEvent:
    event_id: str
    rule: str
    priority: str
    confidence: float
    time: str
    target: IsolationTarget | None
    raw: dict[str, Any]


def _confidence(raw: dict[str, Any], priority: str) -> float:
    value = raw.get("confidence")
    if isinstance(value, int | float) and not isinstance(value, bool) and 0.0 <= float(value) <= 1.0:
        return float(value)
    return PRIORITY_CONFIDENCE.get(priority.lower(), 0.0)


def _target(raw: dict[str, Any]) -> IsolationTarget | None:
    explicit = raw.get("oplia_target")
    if isinstance(explicit, dict):
        kind = str(explicit.get("cloud", "")).lower()
        if kind == "aws" and explicit.get("instance_id") and explicit.get("region"):
            return IsolationTarget("aws", {"region": str(explicit["region"]),
                                           "instance_id": str(explicit["instance_id"])})
        if kind == "azure" and explicit.get("nic_id"):
            return IsolationTarget("azure", {"nic_id": str(explicit["nic_id"])})
        if kind == "k8s" and explicit.get("namespace"):
            return IsolationTarget("k8s", {"namespace": str(explicit["namespace"])})
    fields = raw.get("output_fields")
    if isinstance(fields, dict) and fields.get("k8s.ns.name"):
        return IsolationTarget("k8s", {"namespace": str(fields["k8s.ns.name"])})
    return None


def parse_event(raw: dict[str, Any]) -> ThreatEvent:
    if not isinstance(raw, dict):
        raise ValueError("event must be a JSON object")
    rule = str(raw.get("rule", "unknown"))[:256]
    priority = str(raw.get("priority", "unknown"))[:32]
    time = str(raw.get("time", ""))[:64]
    event_id = str(raw.get("uuid") or raw.get("id") or "") or hashlib.sha256(
        json.dumps(raw, sort_keys=True, default=str).encode()
    ).hexdigest()[:32]
    return ThreatEvent(event_id=event_id[:64], rule=rule, priority=priority,
                       confidence=_confidence(raw, priority), time=time, target=_target(raw), raw=raw)
