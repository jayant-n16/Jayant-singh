from __future__ import annotations

import json
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import update

from oplia_ctl.aiops.engine import AIOpsEngine
from oplia_ctl.aiops.escalation import (
    DEFAULT_POLICY,
    EscalationPolicy,
    EscalationScheduler,
    Prediction,
    PredictionOutOfWindowError,
)
from oplia_ctl.aiops.matrix import DEFAULT_MATRIX
from oplia_ctl.aiops.models import PredictionRow, PredictionStatus
from oplia_ctl.aiops.notify import IncidentNotifier
from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.db import session_scope
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_aiops import FakeNotifier, all_runbooks
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer, signed


class ScriptedNotifier(IncidentNotifier):
    """Per-channel outcome script; records which channels were asked."""

    def __init__(self, outcomes: dict[str, list[str]]) -> None:
        super().__init__([])
        self.outcomes = outcomes
        self.calls: list[tuple[str, list | None]] = []

    @property
    def channel_names(self):
        return ["pagerduty", "slack"]

    def notify(self, incident, phase, only=None):
        self.calls.append((phase, only))
        return {c: self.outcomes[c].pop(0) if self.outcomes[c] else "delivered" for c in (only or [])}


def pred(clock, **over) -> Prediction:
    base = {"risk_id": "risk-1", "service": "checkout-api", "severity": "critical", "probability": 0.8,
            "predicted_at": (clock.now + timedelta(hours=3)).isoformat(),
            "summary": "p99 latency will exceed 800 ms", "metric": "p99_latency_ms"}
    base.update(over)
    return Prediction.model_validate(base)


@pytest.fixture
def sched_factory(session_factory, clock):
    def make(notifier=None, **kw):
        return EscalationScheduler(session_factory=session_factory, notifier=notifier or FakeNotifier(),
                                   clock=clock, **kw)
    return make


def test_submit_window_and_threshold(sched_factory, clock):
    s = sched_factory()
    with pytest.raises(PredictionOutOfWindowError, match="past"):
        s.submit(pred(clock, predicted_at=(clock.now - timedelta(minutes=1)).isoformat()))
    with pytest.raises(PredictionOutOfWindowError, match="240-minute horizon"):
        s.submit(pred(clock, predicted_at=(clock.now + timedelta(hours=4, minutes=1)).isoformat()))
    low = s.submit(pred(clock, severity="low", probability=0.5))
    assert low["outcome"] == "below_threshold" and low["min_probability"] == 0.75


def test_notify_at_follows_lead_time(sched_factory, clock):
    s = sched_factory()
    crit = s.submit(pred(clock))  # 3h ahead, lead 240 min -> clamp to now
    assert crit["notify_at"] == clock.now.isoformat() and crit["channels"] == ["pagerduty", "slack"]
    med = s.submit(pred(clock, risk_id="risk-2", severity="medium"))  # lead 60 min -> now + 2h
    assert med["notify_at"] == (clock.now + timedelta(hours=2)).isoformat() and med["channels"] == ["slack"]


def test_prediction_validation(clock):
    with pytest.raises(ValidationError):
        pred(clock, probability=1.5)
    with pytest.raises(ValidationError):
        pred(clock, predicted_at="2026-11-19T12:00:00")  # naive
    with pytest.raises(ValidationError):
        pred(clock, detail={"x": "y" * 600})


def test_run_due_escalates_once(sched_factory, clock):
    n = FakeNotifier()
    s = sched_factory(n)
    s.submit(pred(clock, severity="medium"))  # due in 2h
    assert s.run_due()["escalated"] == 0 and n.sent == []
    clock.advance(hours=2)
    assert s.run_due()["escalated"] == 1
    incident, phase, only = n.sent[0]
    assert phase == "predicted" and only == ["slack"] and incident.severity == "warning"
    assert incident.dedup_key == "oplia-predict-risk-1"
    assert s.run_due()["escalated"] == 0  # not sent twice
    row = s.list()[0]
    assert row["status"] == "ESCALATED" and row["channels"]["delivered"] == ["slack"]
    # an update after escalation does not re-send or reschedule
    assert s.submit(pred(clock, severity="medium", predicted_at=(clock.now + timedelta(minutes=50)).isoformat()))[
        "outcome"] == "unchanged (ESCALATED)"


def test_partial_failure_retries_only_failed_channel(sched_factory, clock):
    n = ScriptedNotifier({"pagerduty": ["failed: 503"], "slack": ["delivered"]})
    s = sched_factory(n)
    s.submit(pred(clock))
    assert s.run_due() == {"recovered": 0, "escalated": 0, "retrying": 1, "failed": 0, "expired": 0}
    row = s.list()[0]
    assert row["status"] == "SCHEDULED" and row["attempts"] == 1 and row["channels"]["delivered"] == ["slack"]
    assert "pagerduty" in row["last_error"]
    assert s.run_due()["retrying"] == 0  # back-off: not due yet
    clock.advance(minutes=2)
    assert s.run_due()["escalated"] == 1
    assert n.calls[-1] == ("predicted", ["pagerduty"])


def test_gives_up_after_max_attempts(sched_factory, clock):
    n = ScriptedNotifier({"pagerduty": ["failed: x"] * 10, "slack": ["failed: y"] * 10})
    s = sched_factory(n, max_attempts=2)
    s.submit(pred(clock))
    s.run_due()
    clock.advance(minutes=5)
    assert s.run_due()["failed"] == 1
    assert s.list()[0]["status"] == "FAILED"


def test_expires_when_predicted_time_already_passed(sched_factory, clock):
    n = FakeNotifier()
    s = sched_factory(n)
    s.submit(pred(clock, predicted_at=(clock.now + timedelta(minutes=30)).isoformat()))
    clock.advance(minutes=31)  # scheduler was down
    assert s.run_due()["expired"] == 1
    assert n.sent == [] and s.list()[0]["status"] == "EXPIRED"
    # a fresh prediction for the same risk re-arms it
    assert s.submit(pred(clock))["outcome"] == "rearmed"


def test_stale_claim_is_recovered(sched_factory, session_factory, clock):
    s = sched_factory()
    s.submit(pred(clock))
    with session_scope(session_factory) as db:
        db.execute(update(PredictionRow).values(status=PredictionStatus.ESCALATING.value, updated_at=clock.now))
    assert s.run_due()["escalated"] == 0  # claimed by someone else and not stale
    clock.advance(minutes=11)
    report = s.run_due()
    assert report["recovered"] == 1 and report["escalated"] == 1


def test_cancel(sched_factory, clock):
    s = sched_factory()
    pid = s.submit(pred(clock, severity="medium"))["id"]
    assert s.cancel(pid, "alice", "false positive")["status"] == "CANCELLED"
    with pytest.raises(ValueError, match="CANCELLED"):
        s.cancel(pid, "alice", "again")
    with pytest.raises(LookupError):
        s.cancel("nope", "alice", "x")
    clock.advance(hours=3)
    assert s.run_due()["escalated"] == 0
    assert s.submit(pred(clock, severity="medium", predicted_at=(clock.now + timedelta(hours=1)).isoformat()))[
        "outcome"] == "unchanged (CANCELLED)"


def test_policy_must_use_configured_channels(session_factory):
    class OnlySlack(IncidentNotifier):
        @property
        def channel_names(self):
            return ["slack"]

    with pytest.raises(ValueError, match="unconfigured channels"):
        EscalationScheduler(session_factory=session_factory, notifier=OnlySlack([]), policy=DEFAULT_POLICY)
    with pytest.raises(ValueError, match="horizon"):
        EscalationScheduler(session_factory=session_factory, notifier=FakeNotifier(), horizon=timedelta(days=2))
    with pytest.raises(ValidationError):
        EscalationPolicy.model_validate({**DEFAULT_POLICY.model_dump(), "low": {
            "lead_minutes": 0, "channels": ["slack"], "min_probability": 0.5}})


# --------------------------------------------------------------------- API
@pytest.fixture
def aiops_api(gate, session_factory, clock):
    n = FakeNotifier()
    eng = AIOpsEngine(gate=gate, notifier=n, rules=list(DEFAULT_MATRIX), runbooks=all_runbooks(),
                      cluster_name="prod-eks-1", clock=clock)
    sched = EscalationScheduler(session_factory=session_factory, notifier=n, clock=clock)
    secrets = StaticSecretProvider({"webhook_hmac_secret": "hook-secret", "alertmanager_webhook_token": "am-token"})
    app = create_app(
        gate=gate, secrets=secrets,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=[], approver_role="oplia-approver", operator_role="oplia-operator",
        aiops_engine=eng, escalation=sched)
    return TestClient(app)


ALERT = {"alert_id": "am-1", "source": "alertmanager", "cluster": "prod-eks-1", "metric": "p99_latency_ms",
         "value": 1500, "observed_at": "2026-11-19T10:00:00+00:00",
         "workload": {"namespace": "shop", "kind": "Deployment", "name": "checkout"}}


def test_api_alert_webhook(aiops_api):
    body, h = signed(ALERT)
    r = aiops_api.post("/webhooks/aiops/alert", content=body, headers=h)
    assert r.status_code == 202, r.text
    assert r.json()["outcome"] == "proposed" and r.json()["rule"] == "latency-unexplained"
    body, h = signed({**ALERT, "cluster": "elsewhere"})
    assert aiops_api.post("/webhooks/aiops/alert", content=body, headers=h).status_code == 422
    body, h = signed({**ALERT, "value": "fast"})
    assert aiops_api.post("/webhooks/aiops/alert", content=body, headers=h).status_code == 422
    bad = {"X-OPLIA-Timestamp": str(int(time.time())), "X-OPLIA-Signature": "sha256=00",
           "Content-Type": "application/json"}
    assert aiops_api.post("/webhooks/aiops/alert", content=json.dumps(ALERT), headers=bad).status_code == 401


def test_api_predictions(aiops_api, clock):
    p = {"risk_id": "risk-9", "service": "checkout-api", "severity": "high", "probability": 0.9,
         "predicted_at": (clock.now + timedelta(hours=1)).isoformat(), "summary": "disk will fill"}
    body, h = signed(p)
    r = aiops_api.post("/webhooks/aiops/prediction", content=body, headers=h)
    assert r.status_code == 202 and r.json()["outcome"] == "scheduled", r.text
    body, h = signed({**p, "predicted_at": (clock.now + timedelta(hours=9)).isoformat()})
    assert aiops_api.post("/webhooks/aiops/prediction", content=body, headers=h).status_code == 422
    assert aiops_api.get("/aiops/predictions").status_code == 401
    rows = aiops_api.get("/aiops/predictions", headers=bearer("op", "oplia-operator")).json()
    assert [x["risk_id"] for x in rows] == ["risk-9"]
    assert aiops_api.get("/aiops/predictions?status_filter=NOPE",
                         headers=bearer("op", "oplia-operator")).status_code == 400
    pid = rows[0]["id"]
    r = aiops_api.post(f"/aiops/predictions/{pid}/cancel", json={"note": "fp"},
                       headers=bearer("op", "oplia-operator"))
    assert r.status_code == 200 and r.json()["status"] == "CANCELLED"
    assert aiops_api.post(f"/aiops/predictions/{pid}/cancel", json={"note": "fp"},
                          headers=bearer("op", "oplia-operator")).status_code == 409
    assert aiops_api.post("/aiops/predictions/missing/cancel", json={"note": "fp"},
                          headers=bearer("op", "oplia-operator")).status_code == 404


def test_api_aiops_disabled_returns_503(gate):
    app = create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=[], approver_role="oplia-approver", operator_role="oplia-operator")
    c = TestClient(app)
    body, h = signed(ALERT)
    assert c.post("/webhooks/aiops/alert", content=body, headers=h).status_code == 503
    assert c.post("/webhooks/aiops/prediction", content=body, headers=h).status_code == 503
    assert c.get("/aiops/predictions", headers=bearer("op", "oplia-operator")).status_code == 503


AM_ALERT = {"status": "firing", "fingerprint": "3f9a1c0d2b4e5f60",
            "startsAt": "2026-11-19T10:00:00.123Z",
            "labels": {"alertname": "CheckoutLatency", "cluster": "prod-eks-1", "namespace": "shop",
                       "oplia_workload_kind": "Deployment", "oplia_workload_name": "checkout",
                       "oplia_metric": "p99_latency_ms", "oplia_database": "orders"},
            "annotations": {"oplia_value": "1432.5", "summary": "checkout slow",
                            "oplia_correlated": "{\"db_active_connections_ratio\": 0.96}"}}


def test_api_alertmanager_receiver(aiops_api):
    payload = {"version": "4", "status": "firing", "alerts": [
        AM_ALERT,
        {**AM_ALERT, "status": "resolved"},                                   # ignored
        {**AM_ALERT, "fingerprint": "aa11", "annotations": {}},               # no value -> invalid
        {**AM_ALERT, "fingerprint": "bb22", "labels": {**AM_ALERT["labels"], "cluster": "other"}},
        {**AM_ALERT, "fingerprint": ""},
    ]}
    auth = {"Authorization": "Bearer am-token"}
    assert aiops_api.post("/webhooks/aiops/alertmanager", json=payload).status_code == 401
    assert aiops_api.post("/webhooks/aiops/alertmanager", json=payload,
                          headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = aiops_api.post("/webhooks/aiops/alertmanager", json=payload, headers=auth)
    assert r.status_code == 200, r.text
    res = r.json()["results"]
    assert [x["outcome"] for x in res] == ["proposed", "invalid", "rejected", "invalid"]
    assert res[0]["rule"] == "db-pool-saturation" and res[0]["fingerprint"] == "3f9a1c0d2b4e5f60"
    assert "value" in res[1]["error"]
    assert aiops_api.post("/webhooks/aiops/alertmanager", json={"nope": 1}, headers=auth).status_code == 400
    # Alertmanager re-sends the same group: no duplicate proposal
    again = aiops_api.post("/webhooks/aiops/alertmanager", json={"alerts": [AM_ALERT]}, headers=auth).json()
    assert again["results"][0]["outcome"] == "already_proposed"


def test_alertmanager_adapter_parses_promtool_rendered_annotation():
    from oplia_ctl.aiops.alertmanager import to_alerts

    rendered = '{"db_active_connections_ratio": 0.95,\n "cpu_throttle_ratio": 0.30000000000000004}'
    raw = {**AM_ALERT, "annotations": {"oplia_value": "1989.9999999999998", "oplia_correlated": rendered}}
    [(_fp, alert, err)] = to_alerts({"alerts": [raw]})
    assert err is None and alert is not None
    assert alert.value == pytest.approx(1990) and alert.correlated["cpu_throttle_ratio"] == pytest.approx(0.3)
    assert str(alert.observed_at) == "2026-11-19 10:00:00.123000+00:00"
    with pytest.raises(ValueError, match="more than"):
        to_alerts({"alerts": [raw] * 201})


@pytest.mark.skipif(not __import__("os").environ.get("OPLIA_TEST_DATABASE_URL"),
                    reason="row-level concurrency needs PostgreSQL")
def test_two_schedulers_never_send_the_same_prediction_twice(session_factory, clock):
    import threading

    sent: list[str] = []
    lock = threading.Lock()

    class Counting(FakeNotifier):
        def notify(self, incident, phase, only=None):
            with lock:
                sent.append(incident.dedup_key)
            return {c: "delivered" for c in (only or [])}

    s1 = EscalationScheduler(session_factory=session_factory, notifier=Counting(), clock=clock)
    s2 = EscalationScheduler(session_factory=session_factory, notifier=Counting(), clock=clock)
    for i in range(40):
        s1.submit(pred(clock, risk_id=f"risk-{i}"))
    barrier = threading.Barrier(2)

    def run(s):
        barrier.wait()
        s.run_due()

    threads = [threading.Thread(target=run, args=(s,)) for s in (s1, s2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(sent) == sorted(f"oplia-predict-risk-{i}" for i in range(40))
    assert all(r["status"] == "ESCALATED" for r in s1.list(limit=500))
