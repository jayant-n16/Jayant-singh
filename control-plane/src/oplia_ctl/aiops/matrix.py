"""Root-cause metric -> self-healing action matrix.

An alert names one primary metric (``cpu_throttle_ratio``, ``p99_latency_ms`` ...) and may
carry correlated metrics observed at the same time. Rules are evaluated **in order** and the
first match wins, so the most specific rules come first (e.g. latency *with* saturated
database connections maps to a pool flush before plain latency maps to a rolling restart).

The default matrix below can be replaced by a JSON file (``OPLIA_AIOPS_MATRIX_PATH``) with
the same shape; it is validated at start-up and every runbook it names must be registered.
"""

from __future__ import annotations

import json
import operator
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from oplia_ctl.aiops.notify import Severity

MetricName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
FiniteFloat = Annotated[float, Field(allow_inf_nan=False)]
K8sName = Annotated[str, Field(pattern=r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$", max_length=253)]
Namespace = Annotated[str, Field(pattern=r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")]
ActionKind = Literal["k8s.hpa_scale", "k8s.rolling_restart", "runbook", "notify_only"]

_OPS: dict[str, Callable[[float, float], bool]] = {
    ">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le,
}


class Workload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: Namespace
    kind: Literal["Deployment", "StatefulSet", "DaemonSet"]
    name: K8sName
    hpa: K8sName | None = None
    database: Annotated[str, Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$")] | None = None


class Alert(BaseModel):
    """One alert packet from Alertmanager/Datadog/Dynatrace (normalised by the sender)."""

    model_config = ConfigDict(extra="forbid")
    alert_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]
    source: Annotated[str, Field(min_length=1, max_length=128)]
    cluster: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")]
    metric: MetricName
    value: FiniteFloat
    observed_at: AwareDatetime
    correlated: dict[MetricName, FiniteFloat] = Field(default_factory=dict, max_length=20)
    workload: Workload
    summary: Annotated[str, Field(max_length=500)] = ""


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metric: MetricName
    op: Literal[">", ">=", "<", "<="]
    value: FiniteFloat

    def holds(self, observed: float) -> bool:
        return _OPS[self.op](observed, self.value)

    def __str__(self) -> str:
        return f"{self.metric} {self.op} {self.value:g}"


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
    description: Annotated[str, Field(min_length=1, max_length=500)]
    when: Condition
    and_correlated: list[Condition] = Field(default_factory=list, max_length=10)
    requires: list[Literal["hpa", "database"]] = Field(default_factory=list)
    action: ActionKind
    runbook: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,40}$")] | None = None
    severity: Severity = "error"

    @model_validator(mode="after")
    def _runbook_iff_runbook_action(self) -> Rule:
        if (self.action == "runbook") != (self.runbook is not None):
            raise ValueError("'runbook' must be set exactly when action is 'runbook'")
        if self.action == "k8s.hpa_scale" and "hpa" not in self.requires:
            raise ValueError("k8s.hpa_scale rules must require 'hpa'")
        return self

    def matches(self, alert: Alert) -> bool:
        if alert.metric != self.when.metric or not self.when.holds(alert.value):
            return False
        for cond in self.and_correlated:
            observed = alert.correlated.get(cond.metric)
            if observed is None or not cond.holds(observed):
                return False
        if "hpa" in self.requires and alert.workload.hpa is None:
            return False
        return not ("database" in self.requires and alert.workload.database is None)

    def explain(self) -> str:
        parts = [str(self.when), *(str(c) for c in self.and_correlated)]
        return " AND ".join(parts)


DEFAULT_MATRIX: list[Rule] = [
    Rule(name="db-pool-saturation",
         description="Latency with saturated database connections: flush idle pooled connections",
         when=Condition(metric="p99_latency_ms", op=">", value=800),
         and_correlated=[Condition(metric="db_active_connections_ratio", op=">=", value=0.9)],
         requires=["database"], action="runbook", runbook="db-connection-pool-flush"),
    Rule(name="latency-cpu-bound",
         description="Latency caused by CPU throttling: scale out through the HPA",
         when=Condition(metric="p99_latency_ms", op=">", value=800),
         and_correlated=[Condition(metric="cpu_throttle_ratio", op=">", value=0.25)],
         requires=["hpa"], action="k8s.hpa_scale"),
    Rule(name="cpu-throttle-hpa",
         description="Container compute bottleneck: raise HPA headroom",
         when=Condition(metric="cpu_throttle_ratio", op=">", value=0.25),
         requires=["hpa"], action="k8s.hpa_scale"),
    Rule(name="cpu-throttle-no-hpa",
         description="CPU throttling without an HPA: CPU limits must be raised in the manifest "
                     "(a restart would not help), so this is routed to people only",
         when=Condition(metric="cpu_throttle_ratio", op=">", value=0.25),
         action="notify_only", severity="warning"),
    Rule(name="latency-unexplained",
         description="Latency without a correlated cause: rolling restart of the workload",
         when=Condition(metric="p99_latency_ms", op=">", value=800),
         action="k8s.rolling_restart"),
    Rule(name="memory-pressure",
         description="Working set near the memory limit: clear application caches",
         when=Condition(metric="memory_working_set_ratio", op=">=", value=0.9),
         action="runbook", runbook="memory-cache-clear"),
    Rule(name="oom-kills",
         description="Containers OOM-killed: clear application caches",
         when=Condition(metric="oom_kills", op=">", value=0),
         action="runbook", runbook="memory-cache-clear", severity="critical"),
    Rule(name="disk-io-wait",
         description="High disk I/O wait: run the IOPS optimisation runbook",
         when=Condition(metric="disk_io_wait_ratio", op=">", value=0.3),
         action="runbook", runbook="iops-optimize"),
]

_RULES = TypeAdapter(list[Rule])


def load_matrix(path: str) -> list[Rule]:
    if not path:
        return list(DEFAULT_MATRIX)
    rules = _RULES.validate_python(json.loads(Path(path).read_text(encoding="utf-8")))
    names = [r.name for r in rules]
    if len(names) != len(set(names)):
        raise ValueError("rule names in the matrix must be unique")
    if not rules:
        raise ValueError("matrix must contain at least one rule")
    return rules


def evaluate(rules: list[Rule], alert: Alert) -> Rule | None:
    for rule in rules:
        if rule.matches(alert):
            return rule
    return None

