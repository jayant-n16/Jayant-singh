from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from moto import mock_aws

from oplia_ctl.aiops.config import AIOpsSettings
from oplia_ctl.aiops.notify import SlackChannel
from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.config import Settings
from oplia_ctl.finops.config import FinOpsSettings
from oplia_ctl.http import ResilientClient
from oplia_ctl.identity.config import IdentitySettings
from oplia_ctl.integrations import (
    Integration,
    IntegrationRegistry,
    aws_probe,
    build_integrations,
    github_probe,
    jenkins_probe,
    jwks_probe,
    pagerduty_notify,
    slack_notify,
)
from oplia_ctl.secrets import StaticSecretProvider
from oplia_ctl.soar.exporter import SOARSettings
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer

HTTP = ResilientClient(sleep=lambda _s: None)
PD = "https://events.pagerduty.com/v2/enqueue"


def test_status_values_and_no_secret_values():
    sec = StaticSecretProvider({"tok": "super-secret-value"})

    def failing():
        raise RuntimeError("401 Unauthorized password=hunter2")

    reg = IntegrationRegistry([
        Integration("off", "cloud", False),
        Integration("missing", "cicd", True, "x", secrets=("absent",), probe=lambda: "never"),
        Integration("good", "cicd", True, "acme/infra", secrets=("tok",), probe=lambda: "repository reachable"),
        Integration("bad", "identity", True, secrets=("tok",), probe=failing),
        Integration("chat", "alerting", True, secrets=("tok",), notify=lambda actor: "sent"),
        Integration("trigger", "cicd", True, secrets=("tok",)),
    ], sec)
    rows = {r["name"]: r for r in reg.status()}
    assert rows["off"]["status"] == "not_configured"
    assert rows["missing"] == rows["missing"] | {"status": "error", "detail": "secret(s) missing: absent"}
    assert rows["good"]["status"] == "ok" and rows["good"]["detail"] == "repository reachable"
    assert rows["bad"]["status"] == "error" and "hunter2" not in rows["bad"]["detail"]
    assert rows["chat"]["status"] == "configured" and rows["chat"]["can_test_notification"] is True
    assert rows["trigger"]["detail"] == "secret present; no read-only way to verify it"
    assert "super-secret-value" not in json.dumps(rows)
    with pytest.raises(ValueError):
        reg.send_test("good", "alice")
    with pytest.raises(LookupError):
        reg.send_test("nope", "alice")
    assert reg.send_test("chat", "alice") == "sent"


def test_everything_unconfigured_by_default(monkeypatch):
    for k in ("OPLIA_FINOPS_AWS_REGIONS",):
        monkeypatch.delenv(k, raising=False)
    reg = build_integrations(settings=Settings(), secrets=StaticSecretProvider({}), client=HTTP,
                             finops_cfg=FinOpsSettings(), providers={}, identity_cfg=IdentitySettings(),
                             aiops_cfg=AIOpsSettings(), soar_cfg=SOARSettings(), siem_sink=None, alerting_in_use=False)
    rows = reg.status()
    assert {r["name"] for r in rows} == {"aws", "azure", "gcp", "ibm", "github", "gitlab", "jenkins", "oidc-sign-in",
                                         "entra-id", "okta", "active-directory", "slack", "pagerduty", "siem", "vault"}
    assert {r["status"] for r in rows} == {"not_configured"}


@mock_aws
def test_aws_probe_with_moto():
    assert aws_probe("ap-south-1")() == "authenticated to AWS account 123456789012"


@respx.mock
def test_github_jenkins_jwks_probes():
    sec = StaticSecretProvider({"gh": "ghp_x", "ju": "bot", "jt": "tok"})
    gh = respx.get("https://api.github.com/repos/acme/infra").mock(
        return_value=httpx.Response(200, json={"permissions": {"push": True}}))
    assert github_probe(sec, HTTP, "https://api.github.com", "acme/infra", "gh")() == \
        "repository acme/infra reachable (push permission: True)"
    assert gh.calls.last.request.headers["Authorization"] == "Bearer ghp_x"
    respx.get("https://ci.example.com/api/json").mock(return_value=httpx.Response(401))
    with pytest.raises(Exception, match="401"):
        jenkins_probe(sec, HTTP, "https://ci.example.com", "ju", "jt")()
    respx.get("https://idp.example.com/jwks").mock(return_value=httpx.Response(200, json={"keys": [{"kid": "a"}]}))
    assert "1 signing key" in jwks_probe(HTTP, "https://idp.example.com/jwks")()


@respx.mock
def test_pagerduty_test_event_is_triggered_then_resolved():
    route = respx.post(PD).mock(return_value=httpx.Response(202, json={"status": "success"}))
    out = pagerduty_notify(StaticSecretProvider({"pd": "rk"}), HTTP, PD, "pd")("alice")
    assert "resolved" in out
    bodies = [json.loads(c.request.content) for c in route.calls]
    assert [b["event_action"] for b in bodies] == ["trigger", "resolve"]
    assert bodies[0]["dedup_key"] == bodies[1]["dedup_key"] and bodies[0]["payload"]["severity"] == "info"


@respx.mock
def test_slack_test_message():
    hook = "https://hooks.slack.com/services/T000/B000/XXXX"
    route = respx.post(hook).mock(return_value=httpx.Response(200, text="ok"))
    slack = SlackChannel(secrets=StaticSecretProvider({"s": hook}), client=HTTP, webhook_secret="s")
    assert slack_notify(slack)("alice") == "Slack test message sent"
    assert "OPLIA test notification sent by alice" in route.calls.last.request.content.decode()


def test_api_status_and_test_notification(gate):
    sent = []
    reg = IntegrationRegistry([
        Integration("slack", "alerting", True, secrets=("tok",), notify=lambda a: sent.append(a) or "sent"),
        Integration("pagerduty", "alerting", True, secrets=("tok",),
                    notify=lambda a: (_ for _ in ()).throw(RuntimeError("HTTP 400"))),
    ], StaticSecretProvider({"tok": "t"}))
    client = TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=["control-tower-standard"], approver_role="oplia-approver", operator_role="oplia-operator",
        integrations=reg))
    op, ap = bearer("bob", "oplia-operator"), bearer("alice", "oplia-approver")
    assert [r["status"] for r in client.get("/integrations", headers=op).json()] == ["configured", "configured"]
    assert client.post("/integrations/slack/test", headers=op).status_code == 403
    assert client.post("/integrations/nope/test", headers=ap).status_code == 404
    assert client.post("/integrations/slack/test", headers=ap).json() == {
        "integration": "slack", "ok": True, "detail": "sent", "error": None}
    failed = client.post("/integrations/pagerduty/test", headers=ap).json()
    assert failed["ok"] is False and failed["error"] == "RuntimeError: HTTP 400"
    assert sent == ["alice"]
    events = [(e["event"], e["detail"]["integration"]) for e in gate.list_audit(limit=5)]
    assert events[:2] == [("integration_test_notification", "pagerduty"), ("integration_test_notification", "slack")]
