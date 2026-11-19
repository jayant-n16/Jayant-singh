"""Predictive escalation matrix and scheduler.

A predictive risk ("checkout-api p99 will breach 800 ms at 16:40, probability 0.8") is
submitted with ``POST /webhooks/aiops/prediction``. Only predictions inside the horizon
(default 4 hours, as shown in the console) are accepted. The escalation matrix decides, per
severity, **how long before** the predicted time it is routed, **which channels** receive it
and the **minimum probability** worth escalating.

``oplia-aiops-escalator`` runs the scheduler: every interval it claims due predictions
(compare-and-set, safe with several replicas), sends them, and records the outcome. Delivery
is at-least-once: a crash between sending and recording can repeat a Slack message
(PagerDuty de-duplicates by ``dedup_key``). Failed channels are retried with back-off and
already-delivered channels are not sent again; after ``max_attempts`` the row is FAILED.
"""

from __future__ import annotations

import json
import logging
import signal
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.aiops.models import PredictionRow, PredictionStatus
from oplia_ctl.aiops.notify import ChannelName, Incident, IncidentNotifier, Severity
from oplia_ctl.db import session_scope

log = logging.getLogger("oplia.aiops.escalation")

RiskSeverity = Literal["critical", "high", "medium", "low"]
PD_SEVERITY: dict[str, Severity] = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}
_STALE_CLAIM = timedelta(minutes=10)


class EscalationRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lead_minutes: Annotated[int, Field(ge=1, le=1440)]
    channels: list[ChannelName] = Field(min_length=1)
    min_probability: Annotated[float, Field(ge=0.0, le=1.0)]


class EscalationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    critical: EscalationRule
    high: EscalationRule
    medium: EscalationRule
    low: EscalationRule

    def for_severity(self, sev: str) -> EscalationRule:
        rule: EscalationRule = getattr(self, sev)
        return rule


DEFAULT_POLICY = EscalationPolicy(
    critical=EscalationRule(lead_minutes=240, channels=["pagerduty", "slack"], min_probability=0.5),
    high=EscalationRule(lead_minutes=120, channels=["pagerduty", "slack"], min_probability=0.6),
    medium=EscalationRule(lead_minutes=60, channels=["slack"], min_probability=0.6),
    low=EscalationRule(lead_minutes=30, channels=["slack"], min_probability=0.75),
)


class Prediction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    risk_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]
    service: Annotated[str, Field(pattern=r"^[A-Za-z0-9._/-]{1,128}$")]
    severity: RiskSeverity
    probability: Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
    predicted_at: AwareDatetime
    summary: Annotated[str, Field(min_length=1, max_length=500)]
    metric: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")] | None = None
    detail: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=20)

    @model_validator(mode="after")
    def _detail_values_short(self) -> Prediction:
        if any(isinstance(v, str) and len(v) > 500 for v in self.detail.values()):
            raise ValueError("detail values must be at most 500 characters")
        return self


class PredictionOutOfWindowError(ValueError):
    pass


def _aware(dt: datetime) -> datetime:
    # SQLite returns naive UTC, PostgreSQL returns the session time zone: always report UTC
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _row_json(r: PredictionRow) -> dict[str, Any]:
    return {
        "id": r.id, "risk_id": r.risk_id, "service": r.service, "severity": r.severity,
        "probability": r.probability, "predicted_at": _aware(r.predicted_at).isoformat(),
        "notify_at": _aware(r.notify_at).isoformat(), "summary": r.summary, "status": r.status,
        "attempts": r.attempts, "channels": json.loads(r.channels_json),
        "escalated_at": _aware(r.escalated_at).isoformat() if r.escalated_at else None,
        "last_error": r.last_error,
    }


class EscalationScheduler:
    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        notifier: IncidentNotifier,
        policy: EscalationPolicy = DEFAULT_POLICY,
        horizon: timedelta = timedelta(hours=4),
        max_attempts: int = 5,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not timedelta(minutes=15) <= horizon <= timedelta(hours=24):
            raise ValueError("horizon must be between 15 minutes and 24 hours")
        configured = set(notifier.channel_names)
        for sev in ("critical", "high", "medium", "low"):
            missing = set(policy.for_severity(sev).channels) - configured
            if missing:
                raise ValueError(f"escalation policy for {sev} uses unconfigured channels {sorted(missing)}")
        self._sf = session_factory
        self._notifier = notifier
        self._policy = policy
        self._horizon = horizon
        self._max_attempts = max_attempts
        self._clock = clock

    # ------------------------------------------------------------------ submit
    def submit(self, p: Prediction) -> dict[str, Any]:
        now = self._clock()
        if p.predicted_at <= now:
            raise PredictionOutOfWindowError("predicted_at is in the past")
        if p.predicted_at > now + self._horizon:
            raise PredictionOutOfWindowError(
                f"predicted_at is beyond the {int(self._horizon.total_seconds() // 60)}-minute horizon")
        rule = self._policy.for_severity(p.severity)
        if p.probability < rule.min_probability:
            return {"risk_id": p.risk_id, "outcome": "below_threshold",
                    "min_probability": rule.min_probability}
        notify_at = max(now, p.predicted_at - timedelta(minutes=rule.lead_minutes))
        detail = {"metric": p.metric, **p.detail} if p.metric else dict(p.detail)
        channels = json.dumps({"requested": list(rule.channels), "delivered": []})
        with session_scope(self._sf) as s:
            row = s.execute(select(PredictionRow).where(PredictionRow.risk_id == p.risk_id)
                            .with_for_update()).scalar_one_or_none()
            if row is None:
                row = PredictionRow(id=str(uuid.uuid4()), risk_id=p.risk_id, received_at=now, attempts=0)
                s.add(row)
                outcome = "scheduled"
            elif row.status in (PredictionStatus.SCHEDULED, PredictionStatus.EXPIRED, PredictionStatus.FAILED):
                outcome = "rescheduled" if row.status == PredictionStatus.SCHEDULED else "rearmed"
                row.attempts = 0
                row.last_error = None
            else:  # ESCALATING, ESCALATED, CANCELLED: keep the decision / delivery as recorded
                return {"risk_id": p.risk_id, "outcome": f"unchanged ({row.status})", "id": row.id}
            row.service, row.severity, row.probability = p.service, p.severity, p.probability
            row.predicted_at, row.notify_at, row.summary = p.predicted_at, notify_at, p.summary
            row.detail_json = json.dumps(detail, sort_keys=True)
            row.channels_json = channels
            row.status = PredictionStatus.SCHEDULED.value
            row.updated_at = now
            s.flush()
            return {"risk_id": p.risk_id, "outcome": outcome, "id": row.id,
                    "notify_at": notify_at.isoformat(), "channels": list(rule.channels)}

    # ------------------------------------------------------------------- query
    def list(self, status: PredictionStatus | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with session_scope(self._sf) as s:
            q = select(PredictionRow).order_by(PredictionRow.predicted_at).limit(max(1, min(limit, 500)))
            if status is not None:
                q = q.where(PredictionRow.status == status.value)
            return [_row_json(r) for r in s.execute(q).scalars()]

    def cancel(self, prediction_id: str, actor: str, note: str) -> dict[str, Any]:
        now = self._clock()
        with session_scope(self._sf) as s:
            res = s.execute(update(PredictionRow)
                            .where(PredictionRow.id == prediction_id,
                                   PredictionRow.status == PredictionStatus.SCHEDULED.value)
                            .values(status=PredictionStatus.CANCELLED.value, updated_at=now,
                                    last_error=f"cancelled by {actor}: {note}"[:2000]))
            row = s.get(PredictionRow, prediction_id)
            if row is None:
                raise LookupError(prediction_id)
            if res.rowcount != 1:  # type: ignore[attr-defined]
                raise ValueError(f"prediction is {row.status}; only SCHEDULED can be cancelled")
            s.flush()
            return _row_json(row)

    # --------------------------------------------------------------- scheduler
    def _incident(self, r: PredictionRow) -> Incident:
        detail = json.loads(r.detail_json)
        return Incident(
            dedup_key=f"oplia-predict-{r.risk_id}"[:255],
            summary=f"{r.service}: {r.summary} (expected {_aware(r.predicted_at).isoformat()}, "
                    f"probability {r.probability:.0%})",
            severity=PD_SEVERITY[r.severity], source=r.service, klass="predicted-risk",
            component=r.service, group=r.severity,
            details={"risk_id": r.risk_id, "predicted_at": _aware(r.predicted_at).isoformat(),
                     "probability": r.probability, "severity": r.severity, **detail},
        )

    def _recover_stale_claims(self, now: datetime) -> int:
        with session_scope(self._sf) as s:
            res = s.execute(update(PredictionRow)
                            .where(PredictionRow.status == PredictionStatus.ESCALATING.value,
                                   PredictionRow.updated_at < now - _STALE_CLAIM)
                            .values(status=PredictionStatus.SCHEDULED.value, updated_at=now))
            return int(res.rowcount)  # type: ignore[attr-defined]

    def run_due(self, limit: int = 100) -> dict[str, int]:
        now = self._clock()
        report = {"recovered": self._recover_stale_claims(now), "escalated": 0, "retrying": 0,
                  "failed": 0, "expired": 0}
        with session_scope(self._sf) as s:
            ids = list(s.execute(select(PredictionRow.id)
                                 .where(PredictionRow.status == PredictionStatus.SCHEDULED.value,
                                        PredictionRow.notify_at <= now)
                                 .order_by(PredictionRow.notify_at).limit(limit)).scalars())
        for pid in ids:
            with session_scope(self._sf) as s:
                claim = s.execute(update(PredictionRow)
                                  .where(PredictionRow.id == pid,
                                         PredictionRow.status == PredictionStatus.SCHEDULED.value)
                                  .values(status=PredictionStatus.ESCALATING.value, updated_at=now))
                if claim.rowcount != 1:  # type: ignore[attr-defined]
                    continue  # another replica took it
                row = s.get(PredictionRow, pid)
                if row is None:
                    continue
                s.expunge(row)
            report[self._escalate(row, now)] += 1
        return report

    def _escalate(self, row: PredictionRow, now: datetime) -> str:
        channels = json.loads(row.channels_json)
        if _aware(row.predicted_at) <= now:
            self._finish(row.id, PredictionStatus.EXPIRED, now, channels,
                         error="predicted time passed before the prediction could be escalated")
            log.warning("prediction %s expired before escalation", row.risk_id)
            return "expired"
        pending = [c for c in channels["requested"] if c not in channels["delivered"]]
        results = self._notifier.notify(self._incident(row), "predicted", only=pending)
        channels["delivered"] += [c for c, r in results.items() if r in ("delivered", "skipped")]
        failed = {c: r for c, r in results.items() if r not in ("delivered", "skipped")}
        if not failed:
            self._finish(row.id, PredictionStatus.ESCALATED, now, channels, escalated=True)
            return "escalated"
        attempts = row.attempts + 1
        error = "; ".join(f"{c}: {r}" for c, r in failed.items())[:2000]
        if attempts >= self._max_attempts:
            self._finish(row.id, PredictionStatus.FAILED, now, channels, error=error, attempts=attempts)
            return "failed"
        retry_at = now + timedelta(minutes=min(2 ** attempts, 15))
        self._finish(row.id, PredictionStatus.SCHEDULED, now, channels, error=error, attempts=attempts,
                     notify_at=retry_at)
        return "retrying"

    def _finish(self, pid: str, status: PredictionStatus, now: datetime, channels: dict[str, Any], *,
                error: str | None = None, attempts: int | None = None, escalated: bool = False,
                notify_at: datetime | None = None) -> None:
        values: dict[str, Any] = {"status": status.value, "updated_at": now,
                                  "channels_json": json.dumps(channels), "last_error": error}
        if attempts is not None:
            values["attempts"] = attempts
        if escalated:
            values["escalated_at"] = now
        if notify_at is not None:
            values["notify_at"] = notify_at
        with session_scope(self._sf) as s:
            s.execute(update(PredictionRow)
                      .where(PredictionRow.id == pid, PredictionRow.status == PredictionStatus.ESCALATING.value)
                      .values(**values))


def run_forever(scheduler: EscalationScheduler, interval_seconds: float,
                stop: threading.Event | None = None) -> None:
    stop = stop or threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, lambda *_: stop.set())
        except ValueError:  # not in the main thread (tests)
            pass
    while not stop.is_set():
        try:
            report = scheduler.run_due()
            if any(report.values()):
                log.info("escalation run: %s", report)
        except Exception:  # a failed run is logged and retried on the next tick
            log.exception("escalation run failed")
        stop.wait(interval_seconds)
