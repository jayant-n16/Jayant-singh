from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
import respx
from kubernetes.client import (
    V1ObjectMeta,
    V2CrossVersionObjectReference,
    V2HorizontalPodAutoscaler,
    V2HorizontalPodAutoscalerSpec,
    V2HorizontalPodAutoscalerStatus,
    V2MetricSpec,
    V2MetricTarget,
    V2ResourceMetricSource,
)
from kubernetes.client.exceptions import ApiException
from pydantic import ValidationError

from oplia_ctl.aiops.engine import AIOpsEngine, AlertRejectedError
from oplia_ctl.aiops.executors import (
    ACTION_HPA_SCALE,
    ACTION_ROLLING_RESTART,
    ACTION_RUNBOOK,
    RESTART_ANNOTATION,
    AIOpsActionError,
    K8sHpaScaleExecutor,
    K8sRollingRestartExecutor,
    K8sRunbookJobExecutor,
    NotificationRequiredError,
    NotifyBeforeActExecutor,
    job_name,
)
from oplia_ctl.aiops.matrix import DEFAULT_MATRIX, Alert, Rule, evaluate, load_matrix
from oplia_ctl.aiops.notify import (
    PAGERDUTY_EVENTS_URL,
    Incident,
    IncidentNotifier,
    NotificationError,
    PagerDutyChannel,
    SlackChannel,
)
from oplia_ctl.aiops.runbooks import RunbookSpec, load_runbooks
from oplia_ctl.http import ResilientClient
from oplia_ctl.safety import ProposalStatus
from oplia_ctl.secrets import StaticSecretProvider

DIGEST = "a" * 64
SLACK_URL = "https://hooks.slack.com/services/T000/B000/XXXX"
SECRETS = StaticSecretProvider({"pagerduty_routing_key": "R0UTINGKEY", "slack_webhook_url": SLACK_URL})


def alert(**over) -> Alert:
    base = {
        "alert_id": "am-1", "source": "alertmanager", "cluster": "prod-eks-1",
        "metric": "cpu_throttle_ratio", "value": 0.4,
        "observed_at": "2026-11-19T10:00:00+00:00",
        "workload": {"namespace": "shop", "kind": "Deployment", "name": "checkout", "hpa": "checkout"},
    }
    for k, v in over.items():
        if k == "workload":
            base["workload"] = {**base["workload"], **v}
        else:
            base[k] = v
    return Alert.model_validate(base)


def runbook(**over) -> RunbookSpec:
    base = {"id": "db-connection-pool-flush", "description": "flush idle pg connections",
            "image": f"registry.example.com/ops/psql@sha256:{DIGEST}",
            "command": ["/bin/sh", "-c", "psql -v db=\"$(OPLIA_DATABASE)\" -f /runbook.sql"],
            "allowed_namespaces": ["shop"],
            "env": {"APP_DB_USER": "checkout"},
            "secret_env": {"PGPASSWORD": {"secret": "checkout-db", "key": "password"}}}
    base.update(over)
    return RunbookSpec.model_validate(base)


def all_runbooks() -> dict[str, RunbookSpec]:
    return {i: runbook(id=i) for i in ("db-connection-pool-flush", "memory-cache-clear", "iops-optimize")}


class FakeNotifier(IncidentNotifier):
    def __init__(self, outcome: str = "delivered", log: list | None = None) -> None:
        super().__init__([])
        self.sent: list[tuple[Incident, str, list | None]] = []
        self.outcome = outcome
        self.log = log if log is not None else []

    @property
    def channel_names(self) -> list[str]:
        return ["pagerduty", "slack"]

    def notify(self, incident, phase, only=None):
        self.sent.append((incident, phase, only))
        self.log.append(f"notify:{phase}")
        return {c: self.outcome for c in (only or self.channel_names)}


# ------------------------------------------------------------------ matrix
@pytest.mark.parametrize(("over", "rule"), [
    ({"metric": "p99_latency_ms", "value": 1200, "correlated": {"db_active_connections_ratio": 0.95},
      "workload": {"database": "orders"}}, "db-pool-saturation"),
    ({"metric": "p99_latency_ms", "value": 1200, "correlated": {"cpu_throttle_ratio": 0.5}}, "latency-cpu-bound"),
    ({}, "cpu-throttle-hpa"),
    ({"workload": {"hpa": None}}, "cpu-throttle-no-hpa"),
    ({"metric": "p99_latency_ms", "value": 1200}, "latency-unexplained"),
    ({"metric": "p99_latency_ms", "value": 1200, "correlated": {"db_active_connections_ratio": 0.95}},
     "latency-unexplained"),  # pool rule needs the database name
    ({"metric": "memory_working_set_ratio", "value": 0.95}, "memory-pressure"),
    ({"metric": "oom_kills", "value": 2}, "oom-kills"),
    ({"metric": "disk_io_wait_ratio", "value": 0.5}, "disk-io-wait"),
])
def test_default_matrix_maps_rca_to_action(over, rule):
    matched = evaluate(DEFAULT_MATRIX, alert(**over))
    assert matched is not None and matched.name == rule


def test_matrix_no_match_below_threshold():
    assert evaluate(DEFAULT_MATRIX, alert(value=0.1)) is None
    assert evaluate(DEFAULT_MATRIX, alert(metric="unknown_metric", value=99)) is None


def test_rule_validation():
    with pytest.raises(ValidationError, match="runbook"):
        Rule(name="x", description="d", when={"metric": "m", "op": ">", "value": 1}, action="runbook")
    with pytest.raises(ValidationError, match="require 'hpa'"):
        Rule(name="x", description="d", when={"metric": "m", "op": ">", "value": 1}, action="k8s.hpa_scale")


def test_load_matrix(tmp_path):
    assert load_matrix("") == DEFAULT_MATRIX
    rule = DEFAULT_MATRIX[0].model_dump()
    p = tmp_path / "m.json"
    p.write_text(json.dumps([rule, rule]))
    with pytest.raises(ValueError, match="unique"):
        load_matrix(str(p))
    p.write_text(json.dumps([rule]))
    assert [r.name for r in load_matrix(str(p))] == ["db-pool-saturation"]


@pytest.mark.parametrize("over", [
    {"value": float("nan")},
    {"observed_at": "2026-11-19T10:00:00"},           # naive timestamp
    {"workload": {"namespace": "Bad_NS"}},
    {"workload": {"kind": "Pod"}},
    {"alert_id": "x" * 200},
    {"extra": 1},
])
def test_alert_validation(over):
    with pytest.raises(ValidationError):
        alert(**over)


# ---------------------------------------------------------------- runbooks
@pytest.mark.parametrize(("over", "msg"), [
    ({"image": "registry.example.com/ops/psql:latest"}, "pattern"),
    ({"image": f"registry.example.com/ops/psql@sha256:{'0' * 64}"}, "placeholder"),
    ({"env": {"OPLIA_X": "1"}}, "reserved"),
    ({"allowed_namespaces": []}, "at least 1"),
    ({"timeout_seconds": 5}, "greater than or equal"),
])
def test_runbook_validation(over, msg):
    with pytest.raises(ValidationError, match=msg):
        runbook(**over)


def test_load_runbooks(tmp_path):
    assert load_runbooks("") == {}
    spec = runbook().model_dump()
    p = tmp_path / "r.json"
    p.write_text(json.dumps([spec, spec]))
    with pytest.raises(ValueError, match="duplicate"):
        load_runbooks(str(p))
    p.write_text(json.dumps([{**spec, "env": {"PGPASSWORD": "x"}}]))
    with pytest.raises(ValueError, match="both env and secret_env"):
        load_runbooks(str(p))
    p.write_text(json.dumps([spec]))
    assert list(load_runbooks(str(p))) == ["db-connection-pool-flush"]


# ------------------------------------------------------------ notification
INCIDENT = Incident(dedup_key="oplia-aiops-abc", summary="checkout <slow> & hot", severity="error",
                    source="prod-eks-1/shop", klass="p99_latency_ms", component="Deployment/checkout",
                    group="shop", details={"rule": "latency-unexplained", "note": "<b>x</b> & y"},
                    links=(("https://oplia.example.com/proposals/1", "Review"),))


def http() -> ResilientClient:
    return ResilientClient(sleep=lambda _s: None, max_retries=1)


@respx.mock
def test_pagerduty_events_v2_payload():
    route = respx.post(PAGERDUTY_EVENTS_URL).mock(return_value=httpx.Response(202, json={"status": "success"}))
    ch = PagerDutyChannel(secrets=SECRETS, client=http(), routing_key_secret="pagerduty_routing_key",
                          clock=lambda: datetime(2026, 11, 19, 10, tzinfo=UTC))
    assert ch.send(INCIDENT, "pre_action") is True
    body = json.loads(route.calls.last.request.content)
    assert body["routing_key"] == "R0UTINGKEY" and body["event_action"] == "trigger"
    assert body["dedup_key"] == "oplia-aiops-abc"
    assert body["payload"]["severity"] == "error"
    assert body["payload"]["summary"].startswith("[Self-healing action starting]")
    assert body["payload"]["custom_details"]["phase"] == "pre_action"
    assert body["links"] == [{"href": "https://oplia.example.com/proposals/1", "text": "Review"}]
    assert ch.send(INCIDENT, "result") is False  # left open for a human
    assert route.call_count == 1


@respx.mock
def test_pagerduty_failures_raise_notification_error():
    respx.post(PAGERDUTY_EVENTS_URL).mock(return_value=httpx.Response(400, json={"status": "invalid"}))
    ch = PagerDutyChannel(secrets=SECRETS, client=http(), routing_key_secret="pagerduty_routing_key")
    with pytest.raises(NotificationError, match="PagerDuty"):
        ch.send(INCIDENT, "opened")
    missing = PagerDutyChannel(secrets=StaticSecretProvider({}), client=http(), routing_key_secret="nope")
    with pytest.raises(NotificationError, match="secret missing"):
        missing.send(INCIDENT, "opened")
    with pytest.raises(ValueError, match="https"):
        PagerDutyChannel(secrets=SECRETS, client=http(), routing_key_secret="k", events_url="http://x")


@respx.mock
def test_slack_message_and_errors_never_leak_url():
    route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200, text="ok"))
    ch = SlackChannel(secrets=SECRETS, client=http(), webhook_secret="slack_webhook_url")
    assert ch.send(INCIDENT, "opened") is True
    msg = json.loads(route.calls.last.request.content)
    assert msg["blocks"][0]["type"] == "header"
    section = msg["blocks"][1]["text"]["text"]
    assert "*note:* &lt;b&gt;x&lt;/b&gt; &amp; y" in section  # mrkdwn is escaped
    assert msg["blocks"][0]["text"]["type"] == "plain_text"  # header needs no escaping
    assert "*rule:* latency-unexplained" in section
    assert "<https://oplia.example.com/proposals/1|Review>" in section
    respx.post(SLACK_URL).mock(return_value=httpx.Response(404, text="no_service"))
    with pytest.raises(NotificationError) as ei:
        ch.send(INCIDENT, "opened")
    assert SLACK_URL not in str(ei.value) and "404" in str(ei.value)
    bad = SlackChannel(secrets=StaticSecretProvider({"s": "https://evil.example.com/x"}), client=http(),
                       webhook_secret="s")
    with pytest.raises(NotificationError, match=r"hooks\.slack\.com"):
        bad.send(INCIDENT, "opened")


def test_notifier_reports_per_channel():
    class Boom:
        name = "slack"

        def send(self, incident, phase):
            raise NotificationError("down")

    class Ok:
        name = "pagerduty"

        def send(self, incident, phase):
            return True

    n = IncidentNotifier([Ok(), Boom()])
    res = n.notify(INCIDENT, "opened")
    assert res == {"pagerduty": "delivered", "slack": "failed: down"}
    assert IncidentNotifier.any_delivered(res)
    assert IncidentNotifier([Ok()]).notify(INCIDENT, "predicted", only=["slack"]) == {
        "slack": "failed: channel not configured"}
    with pytest.raises(ValueError, match="duplicate"):
        IncidentNotifier([Ok(), Ok()])


# ------------------------------------------------------------------ engine
@pytest.fixture
def notifier():
    return FakeNotifier()


@pytest.fixture
def engine(gate, notifier, clock):
    return AIOpsEngine(gate=gate, notifier=notifier, rules=list(DEFAULT_MATRIX), runbooks=all_runbooks(),
                       cluster_name="prod-eks-1", cooldown=timedelta(minutes=30),
                       public_base_url="https://oplia.example.com", clock=clock)


def test_engine_proposes_and_notifies(engine, gate, notifier):
    res = engine.handle(alert())
    assert res["outcome"] == "proposed" and res["rule"] == "cpu-throttle-hpa"
    p = gate.get(res["proposal_id"])
    assert p.action_type == ACTION_HPA_SCALE and p.status is ProposalStatus.PENDING
    assert p.payload["hpa"] == "checkout" and p.payload["incident"]["severity"] == "error"
    assert p.target == "prod-eks-1/Deployment/shop/checkout"
    incident, phase, _ = notifier.sent[-1]
    assert phase == "opened" and incident.details["proposal_id"] == p.id
    assert incident.links == ((f"https://oplia.example.com/proposals/{p.id}", "Review proposal"),)


def test_engine_rejects_foreign_cluster_and_protected_namespace(engine, notifier):
    with pytest.raises(AlertRejectedError, match="cluster"):
        engine.handle(alert(cluster="other"))
    with pytest.raises(AlertRejectedError, match="protected"):
        engine.handle(alert(workload={"namespace": "kube-system"}))
    with pytest.raises(AlertRejectedError, match="protected"):
        engine.handle(alert(workload={"namespace": "openshift-monitoring"}))
    assert notifier.sent == []


def test_engine_dedup_while_open_and_cooldown(engine, gate, notifier, clock):
    first = engine.handle(alert())
    again = engine.handle(alert(alert_id="am-2"))
    assert again["outcome"] == "already_proposed" and again["proposal_id"] == first["proposal_id"]
    assert len(notifier.sent) == 1  # no second page

    gate.reject(first["proposal_id"], "alice", "not now")
    clock.advance(minutes=10)
    assert engine.handle(alert(alert_id="am-3"))["outcome"] == "cooldown"
    clock.advance(minutes=21)
    later = engine.handle(alert(alert_id="am-4"))
    assert later["outcome"] == "proposed" and later["proposal_id"] != first["proposal_id"]


def test_engine_expired_proposal_counts_from_expiry(engine, clock):
    first = engine.handle(alert())
    clock.advance(minutes=61)  # proposal TTL is 60 minutes -> EXPIRED at minute 60
    res = engine.handle(alert(alert_id="am-9"))
    assert res["outcome"] == "cooldown"
    clock.advance(minutes=30)
    assert engine.handle(alert(alert_id="am-10"))["outcome"] == "proposed"
    assert first["proposal_id"]


def test_engine_concurrent_duplicate_is_not_paged_twice(engine, gate, notifier, monkeypatch):
    engine.handle(alert())
    monkeypatch.setattr(gate, "latest_by_idempotency_prefix", lambda _p: None)  # lose the race
    res = engine.handle(alert(alert_id="am-race"))
    assert res["outcome"] == "already_proposed"
    assert len(notifier.sent) == 1


def test_engine_notify_only_paths(engine, gate, notifier):
    res = engine.handle(alert(workload={"hpa": None}))
    assert res["outcome"] == "notified_only" and res["rule"] == "cpu-throttle-no-hpa"
    res = engine.handle(alert(metric="queue_depth", value=10))
    assert res["outcome"] == "notified_only" and res["rule"] is None
    res = engine.handle(alert(metric="memory_working_set_ratio", value=0.95, workload={"namespace": "payments"}))
    assert res["outcome"] == "notified_only" and "not allowed" in res["reason"]
    assert gate.list() == []
    assert [phase for _, phase, _ in notifier.sent] == ["opened"] * 3


def test_engine_runbook_payload(engine, gate):
    res = engine.handle(alert(metric="p99_latency_ms", value=1500,
                              correlated={"db_active_connections_ratio": 0.97}, workload={"database": "orders"}))
    p = gate.get(res["proposal_id"])
    assert p.action_type == ACTION_RUNBOOK
    assert p.payload["runbook"] == "db-connection-pool-flush" and p.payload["database"] == "orders"
    assert len(p.payload["job_suffix"]) == 12


def test_engine_validates_configuration(gate, notifier):
    with pytest.raises(ValueError, match="unregistered runbooks"):
        AIOpsEngine(gate=gate, notifier=notifier, rules=list(DEFAULT_MATRIX), runbooks={}, cluster_name="c")
    with pytest.raises(ValueError, match="cluster_name"):
        AIOpsEngine(gate=gate, notifier=notifier, rules=[], runbooks={}, cluster_name="")
    with pytest.raises(ValueError, match="https"):
        AIOpsEngine(gate=gate, notifier=notifier, rules=[], runbooks={}, cluster_name="c",
                    public_base_url="http://x")


# --------------------------------------------------------------- executors
WL = {"namespace": "shop", "kind": "Deployment", "name": "checkout"}


class FakeApps:
    def __init__(self):
        self.calls = []

    def _patch(self, kind):
        def f(name, namespace, body):
            self.calls.append((kind, name, namespace, body))
            return SimpleNamespace(metadata=SimpleNamespace(generation=7))
        return f

    def __getattr__(self, item):
        mapping = {"patch_namespaced_deployment": "Deployment", "patch_namespaced_stateful_set": "StatefulSet",
                   "patch_namespaced_daemon_set": "DaemonSet"}
        if item in mapping:
            return self._patch(mapping[item])
        raise AttributeError(item)


@pytest.mark.parametrize("kind", ["Deployment", "StatefulSet", "DaemonSet"])
def test_rolling_restart(kind):
    api = FakeApps()
    ex = K8sRollingRestartExecutor(api_factory=lambda: api, clock=lambda: datetime(2026, 11, 19, 10, tzinfo=UTC))
    res = ex({**WL, "kind": kind})
    assert api.calls == [(kind, "checkout", "shop",
                          {"spec": {"template": {"metadata": {"annotations": {
                              RESTART_ANNOTATION: "2026-11-19T10:00:00Z"}}}}})]
    assert res["generation"] == 7


@pytest.mark.parametrize("payload", [
    {**WL, "namespace": "kube-system"}, {**WL, "namespace": "default"}, {**WL, "kind": "Pod"},
    {**WL, "name": "Bad Name"}, {**WL, "namespace": "openshift-ingress"},
])
def test_rolling_restart_refuses(payload):
    api = FakeApps()
    with pytest.raises(ValueError):
        K8sRollingRestartExecutor(api_factory=lambda: api)(payload)
    assert api.calls == []


def make_hpa(max_r=5, current=5, cpu=70, kind="Deployment", name="checkout", rv="100"):
    metrics = [] if cpu is None else [V2MetricSpec(type="Resource", resource=V2ResourceMetricSource(
        name="cpu", target=V2MetricTarget(type="Utilization", average_utilization=cpu)))]
    return V2HorizontalPodAutoscaler(
        metadata=V1ObjectMeta(name="checkout", namespace="shop", resource_version=rv),
        spec=V2HorizontalPodAutoscalerSpec(max_replicas=max_r, min_replicas=1, metrics=metrics,
                                           scale_target_ref=V2CrossVersionObjectReference(
                                               api_version="apps/v1", kind=kind, name=name)),
        status=V2HorizontalPodAutoscalerStatus(current_replicas=current, desired_replicas=current))


class FakeAutoscaling:
    def __init__(self, hpa, apply=True):
        self.hpa = hpa
        self.apply = apply
        self.patches = []

    def read_namespaced_horizontal_pod_autoscaler(self, name, namespace):
        return self.hpa

    def patch_namespaced_horizontal_pod_autoscaler(self, name, namespace, body):
        self.patches.append(body)
        if body["metadata"]["resourceVersion"] != self.hpa.metadata.resource_version:
            raise ApiException(status=409, reason="Conflict")
        if not self.apply:
            return self.hpa
        if "maxReplicas" in body["spec"]:
            self.hpa.spec.max_replicas = body["spec"]["maxReplicas"]
        if "metrics" in body["spec"]:
            new = body["spec"]["metrics"][0]["resource"]["target"]["averageUtilization"]
            self.hpa.spec.metrics[0].resource.target.average_utilization = new
        self.hpa.metadata.resource_version = str(int(self.hpa.metadata.resource_version) + 1)
        return self.hpa


def hpa_ex(api, **kw):
    cfg = {"max_step": 2, "max_ceiling": 6, "cpu_target_step": 10, "cpu_target_floor": 40, **kw}
    return K8sHpaScaleExecutor(api_factory=lambda: api, **cfg)


def test_hpa_raises_max_when_capped():
    api = FakeAutoscaling(make_hpa(max_r=5, current=5))
    res = hpa_ex(api)({**WL, "hpa": "checkout"})
    assert res["change"] == {"field": "maxReplicas", "from": 5, "to": 6}  # capped at ceiling 6
    assert api.patches[0] == {"metadata": {"resourceVersion": "100"}, "spec": {"maxReplicas": 6}}
    assert res["verified"] is True


def test_hpa_at_ceiling_refuses():
    api = FakeAutoscaling(make_hpa(max_r=6, current=6))
    with pytest.raises(AIOpsActionError, match="ceiling"):
        hpa_ex(api)({**WL, "hpa": "checkout"})
    assert api.patches == []


def test_hpa_lowers_cpu_target_when_not_capped():
    api = FakeAutoscaling(make_hpa(max_r=10, current=3, cpu=45))
    res = hpa_ex(api)({**WL, "hpa": "checkout"})
    assert res["change"] == {"field": "cpu averageUtilization", "from": 45, "to": 40}  # floor 40
    sent = api.patches[0]["spec"]["metrics"]
    assert sent == [{"type": "Resource", "resource": {"name": "cpu", "target": {
        "type": "Utilization", "averageUtilization": 40}}}]


@pytest.mark.parametrize(("hpa", "msg"), [
    (make_hpa(max_r=10, current=3, cpu=None), "no CPU utilisation target"),
    (make_hpa(max_r=10, current=3, cpu=40), "floor"),
    (make_hpa(name="other"), "targets Deployment/other"),
])
def test_hpa_refusals(hpa, msg):
    api = FakeAutoscaling(hpa)
    with pytest.raises(AIOpsActionError, match=msg):
        hpa_ex(api)({**WL, "hpa": "checkout"})
    assert api.patches == []


def test_hpa_verify_after_patch_detects_no_effect():
    api = FakeAutoscaling(make_hpa(max_r=5, current=5), apply=False)
    with pytest.raises(AIOpsActionError, match="did not reflect"):
        hpa_ex(api)({**WL, "hpa": "checkout"})


def test_hpa_executor_bounds():
    with pytest.raises(ValueError):
        K8sHpaScaleExecutor(max_step=0, max_ceiling=5, cpu_target_step=10, cpu_target_floor=40)
    with pytest.raises(ValueError):
        K8sHpaScaleExecutor(max_step=1, max_ceiling=5, cpu_target_step=10, cpu_target_floor=5)


class FakeBatch:
    def __init__(self, status=None):
        self.created = []
        self.status = status

    def create_namespaced_job(self, namespace, body):
        if self.status:
            raise ApiException(status=self.status, reason="x")
        self.created.append((namespace, body))


RB_PAYLOAD = {**WL, "runbook": "db-connection-pool-flush", "database": "orders", "alert_id": "am-1",
              "job_suffix": "0123456789ab"}


def test_runbook_job_is_hardened_and_fixed():
    api = FakeBatch()
    ex = K8sRunbookJobExecutor(all_runbooks(), api_factory=lambda: api)
    res = ex(RB_PAYLOAD)
    ns, job = api.created[0]
    assert ns == "shop" and res["created"] is True
    assert job["metadata"]["name"] == "oplia-rb-db-connection-pool-flush-0123456789ab"
    assert len(job["metadata"]["name"]) <= 63
    spec = job["spec"]
    assert spec["backoffLimit"] == 0 and spec["activeDeadlineSeconds"] == 600
    pod = spec["template"]["spec"]
    c = pod["containers"][0]
    assert c["image"].endswith("@sha256:" + DIGEST)
    assert c["command"] == runbook().command  # never taken from the alert
    assert c["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}}
    assert pod["securityContext"]["runAsNonRoot"] is True and pod["automountServiceAccountToken"] is False
    env = {e["name"]: e for e in c["env"]}
    assert env["OPLIA_DATABASE"]["value"] == "orders" and env["APP_DB_USER"]["value"] == "checkout"
    assert env["PGPASSWORD"]["valueFrom"] == {"secretKeyRef": {"name": "checkout-db", "key": "password"}}


def test_runbook_job_refusals_and_conflict():
    rbs = all_runbooks()
    with pytest.raises(ValueError, match="not allowed in namespace"):
        K8sRunbookJobExecutor(rbs, api_factory=FakeBatch).describe({**RB_PAYLOAD, "namespace": "payments"})
    with pytest.raises(ValueError, match="not registered"):
        K8sRunbookJobExecutor(rbs, api_factory=FakeBatch).describe({**RB_PAYLOAD, "runbook": "rm-rf"})
    with pytest.raises(ValueError, match="database"):
        K8sRunbookJobExecutor(rbs, api_factory=FakeBatch).describe({**RB_PAYLOAD, "database": "x; DROP"})
    assert K8sRunbookJobExecutor(rbs, api_factory=lambda: FakeBatch(409))(RB_PAYLOAD)["created"] is False
    with pytest.raises(ApiException):
        K8sRunbookJobExecutor(rbs, api_factory=lambda: FakeBatch(403))(RB_PAYLOAD)
    assert len(job_name("a" * 41, "0123456789ab")) <= 63


class RecordingInner:
    def __init__(self, log, fail=False):
        self.log = log
        self.fail = fail

    def describe(self, payload):
        return "inner action"

    def __call__(self, payload):
        self.log.append("act")
        if self.fail:
            raise RuntimeError("k8s said no")
        return {"done": True}


INC_PAYLOAD = {"incident": {"dedup_key": "d", "summary": "s", "severity": "error", "source": "src",
                            "klass": "k", "details": {"rule": "r"}}}


def test_notify_before_act_order_and_result():
    log: list[str] = []
    n = FakeNotifier(log=log)
    res = NotifyBeforeActExecutor(RecordingInner(log), n)(INC_PAYLOAD)
    assert log == ["notify:pre_action", "act", "notify:result"]
    assert res["done"] is True and res["notifications"]["pre_action"]["pagerduty"] == "delivered"
    assert n.sent[-1][0].details["outcome"] == "EXECUTED"


def test_notify_before_act_refuses_without_delivery():
    log: list[str] = []
    with pytest.raises(NotificationRequiredError):
        NotifyBeforeActExecutor(RecordingInner(log), FakeNotifier("failed: x", log=log))(INC_PAYLOAD)
    assert "act" not in log
    log.clear()
    NotifyBeforeActExecutor(RecordingInner(log), FakeNotifier("failed: x", log=log),
                            require_delivery=False)(INC_PAYLOAD)
    assert "act" in log


def test_notify_before_act_reports_failure():
    log: list[str] = []
    n = FakeNotifier(log=log)
    with pytest.raises(RuntimeError, match="k8s said no"):
        NotifyBeforeActExecutor(RecordingInner(log, fail=True), n)(INC_PAYLOAD)
    assert n.sent[-1][1] == "result" and n.sent[-1][0].details["outcome"] == "FAILED"


def test_end_to_end_through_gate(engine, gate):
    api = FakeApps()
    res = engine.handle(alert(metric="p99_latency_ms", value=1500))
    p = gate.get(res["proposal_id"])
    assert p.action_type == ACTION_ROLLING_RESTART
    gate.approve(p.id, "alice")
    log: list[str] = []
    ex = NotifyBeforeActExecutor(K8sRollingRestartExecutor(api_factory=lambda: api), FakeNotifier(log=log))
    done = gate.execute(p.id, ex, "bob")
    assert done.status is ProposalStatus.EXECUTED
    assert api.calls[0][0:3] == ("Deployment", "checkout", "shop")
    assert log[0] == "notify:pre_action"

    # a second proposal whose pre-action page cannot be delivered must FAIL without touching k8s
    gate2 = engine
    res2 = gate2.handle(alert(metric="memory_working_set_ratio", value=0.95, alert_id="mem-1"))
    gate.approve(res2["proposal_id"], "alice")
    batch = FakeBatch()
    ex2 = NotifyBeforeActExecutor(K8sRunbookJobExecutor(all_runbooks(), api_factory=lambda: batch),
                                  FakeNotifier("failed: down"))
    failed = gate.execute(res2["proposal_id"], ex2, "bob")
    assert failed.status is ProposalStatus.FAILED
    assert failed.result is not None and failed.result["error_type"] == "NotificationRequiredError"
    assert batch.created == []


def test_example_runbooks_are_valid_except_digest(tmp_path):
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "examples" / "aiops" / "runbooks.example.json"
    text = example.read_text()
    with pytest.raises(ValidationError, match="image"):
        load_runbooks(str(example))  # placeholders must never load by accident
    pinned = tmp_path / "rb.json"
    pinned.write_text(text.replace("REPLACE_WITH_PINNED_DIGEST", "c" * 64))
    registry = load_runbooks(str(pinned))
    assert set(registry) == {r.runbook for r in DEFAULT_MATRIX if r.runbook}
