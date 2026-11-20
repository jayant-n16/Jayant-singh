from __future__ import annotations

import json
import time

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier, sign_webhook
from oplia_ctl.config import CICDTarget
from oplia_ctl.drivers.cicd import build_cicd_driver
from oplia_ctl.http import ResilientClient
from oplia_ctl.remediation.drift import ACTION_DRIFT_REMEDIATE, DriftRemediationExecutor
from oplia_ctl.secrets import StaticSecretProvider
from oplia_ctl.soar.exporter import SOARExporter
from oplia_ctl.soar.siem import SIEMSink

ISS, AUD = "https://idp.example.com/", "oplia-api"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SECRETS = StaticSecretProvider({"webhook_hmac_secret": "hook-secret", "github_dispatch_token": "ghp",
                                "siem_token": "tok"})
SIEM = "https://siem.example.com/ingest"


def bearer(sub, *roles):
    now = int(time.time())
    tok = jwt.encode({"iss": ISS, "aud": AUD, "sub": sub, "iat": now, "exp": now + 300, "roles": list(roles)},
                     KEY, algorithm="RS256")
    return {"Authorization": f"Bearer {tok}"}


def signed(payload, delivery="dlv-1"):
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    return body, {"X-OPLIA-Timestamp": ts, "X-OPLIA-Signature": sign_webhook("hook-secret", ts, body),
                  "X-OPLIA-Delivery": delivery, "Content-Type": "application/json"}


@pytest.fixture
def api(gate, tmp_path):
    http = ResilientClient(sleep=lambda _s: None)
    cfg = CICDTarget(github_repository="acme/infra")
    sink = SIEMSink(endpoint=SIEM, fmt="generic", token_secret="siem_token", secrets=SECRETS, client=http,
                    dead_letter_path=str(tmp_path / "dlq"))
    app = create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={ACTION_DRIFT_REMEDIATE: DriftRemediationExecutor(
            lambda n: build_cicd_driver(n, cfg, SECRETS, http))},
        webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=["control-tower-standard", "alz-hybrid"],
        approver_role="oplia-approver", operator_role="oplia-operator",
        soar_exporter=SOARExporter(gate=gate, sink=sink),
    )
    return TestClient(app)


DRIFT = {"zone_name": "prod-zone-1", "cloud": "aws", "account_id": "123456789012",
         "blueprint": "control-tower-standard", "target_cicd": "github"}


@respx.mock
def test_end_to_end_drift_flow(api):
    dispatch = respx.post("https://api.github.com/repos/acme/infra/dispatches").mock(
        return_value=httpx.Response(204))
    body, h = signed(DRIFT)
    r = api.post("/webhooks/drift", content=body, headers=h)
    assert r.status_code == 202, r.text
    pid = r.json()["id"]
    assert r.json()["status"] == "PENDING"

    # Execution before approval is refused and nothing is dispatched.
    assert api.post(f"/proposals/{pid}/execute", headers=bearer("op", "oplia-operator")).status_code == 409
    assert not dispatch.called

    # An operator cannot approve; an approver can.
    assert api.post(f"/proposals/{pid}/approve", json={}, headers=bearer("op", "oplia-operator")).status_code == 403
    assert api.post(f"/proposals/{pid}/approve", json={"note": "ok"},
                    headers=bearer("bob", "oplia-approver")).json()["status"] == "APPROVED"

    done = api.post(f"/proposals/{pid}/execute", headers=bearer("op", "oplia-operator")).json()
    assert done["status"] == "EXECUTED" and dispatch.called
    assert api.get("/audit/verify", headers=bearer("bob", "oplia-approver")).json() == {"intact": True}


def test_duplicate_delivery_is_idempotent(api):
    body, h = signed(DRIFT, delivery="same")
    a = api.post("/webhooks/drift", content=body, headers=h).json()["id"]
    body, h = signed(DRIFT, delivery="same")
    b = api.post("/webhooks/drift", content=body, headers=h).json()["id"]
    assert a == b


@pytest.mark.parametrize("mutate,code", [
    (lambda b, h: (b, {**h, "X-OPLIA-Signature": "sha256=" + "0" * 64}), 401),
    (lambda b, h: (b + b" ", h), 401),
    (lambda b, h: (b, {k: v for k, v in h.items() if k != "X-OPLIA-Delivery"}), 400),
])
def test_webhook_rejects_tampering(api, mutate, code):
    body, h = mutate(*signed(DRIFT))
    assert api.post("/webhooks/drift", content=body, headers=h).status_code == code


def test_webhook_rejects_invalid_payloads(api):
    for bad in [DRIFT | {"blueprint": "not-allowed"}, DRIFT | {"zone_name": "x;rm -rf"},
                DRIFT | {"target_cicd": "circleci"}, DRIFT | {"extra": 1}]:
        body, h = signed(bad, delivery=str(hash(json.dumps(bad, sort_keys=True))))
        assert api.post("/webhooks/drift", content=body, headers=h).status_code == 422


def test_api_requires_valid_token(api):
    assert api.get("/proposals").status_code == 401
    assert api.get("/proposals", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert api.get("/proposals", headers=bearer("x", "some-other-role")).status_code == 403


def test_kill_switch_endpoint_blocks_execution(api):
    body, h = signed(DRIFT)
    pid = api.post("/webhooks/drift", content=body, headers=h).json()["id"]
    api.post(f"/proposals/{pid}/approve", json={}, headers=bearer("bob", "oplia-approver"))
    r = api.post("/kill-switch", json={"engaged": True, "reason": "incident 42"},
                 headers=bearer("bob", "oplia-approver"))
    assert r.json() == {"engaged": True}
    assert api.post(f"/proposals/{pid}/execute", headers=bearer("op", "oplia-operator")).status_code == 423


def test_self_approval_forbidden_for_human_requests(api, gate):
    p = gate.propose(action_type=ACTION_DRIFT_REMEDIATE, target="t", payload={}, reason="r", requested_by="bob")
    r = api.post(f"/proposals/{p.id}/approve", json={}, headers=bearer("bob", "oplia-approver"))
    assert r.status_code == 403


@respx.mock
def test_runtime_threat_webhook(api):
    respx.post(SIEM).mock(return_value=httpx.Response(202))
    ev = {"uuid": "e-9", "rule": "Write below etc", "priority": "Critical",
          "output_fields": {"k8s.ns.name": "payments"}}
    body, h = signed(ev)
    r = api.post("/webhooks/runtime-threat", content=body, headers=h)
    assert r.status_code == 202 and r.json()["exported"] is True and r.json()["proposal_id"]


def test_health(api):
    assert api.get("/healthz").json() == {"status": "ok"}
    assert api.get("/readyz").json() == {"status": "ready"}


def test_me_reports_roles_and_capabilities(api):
    me = api.get("/me", headers=bearer("carol", "oplia-approver", "oplia-operator")).json()
    assert me["subject"] == "carol" and me["roles"] == ["oplia-approver", "oplia-operator"]
    assert me["can"] == {"approve": True, "operate": True, "read": True}
    assert me["features"] == {"aiops": False, "finops": False, "jit": False, "dr": False,
                              "inventory": False, "databases": False, "consistency": False}
    nobody = api.get("/me", headers=bearer("dave")).json()  # signed in, no role: allowed, can nothing
    assert nobody["can"] == {"approve": False, "operate": False, "read": False}
    assert api.get("/me").status_code == 401


def test_kill_switch_state_and_audit_events(api):
    assert api.get("/kill-switch", headers=bearer("op", "oplia-operator")).json() == {
        "engaged": False, "set_by": None, "set_at": None, "reason": None}
    assert api.get("/kill-switch", headers=bearer("dave")).status_code == 403
    api.post("/kill-switch", json={"engaged": True, "reason": "incident 7"}, headers=bearer("bob", "oplia-approver"))
    state = api.get("/kill-switch", headers=bearer("op", "oplia-operator")).json()
    assert state["engaged"] is True and state["set_by"] == "bob" and state["reason"] == "incident 7"
    assert state["set_at"].endswith("+00:00")
    for i in range(3):
        body, h = signed(DRIFT | {"zone_name": f"zone-{i}"}, delivery=f"d-{i}")
        api.post("/webhooks/drift", content=body, headers=h)
    approver = bearer("bob", "oplia-approver")
    assert api.get("/audit/events", headers=bearer("op", "oplia-operator")).status_code == 403
    page1 = api.get("/audit/events", params={"limit": 2}, headers=approver).json()
    assert [e["seq"] for e in page1] == [4, 3] and page1[0]["event"] == "proposed"
    page2 = api.get("/audit/events", params={"limit": 10, "before_seq": page1[-1]["seq"]}, headers=approver).json()
    assert [e["seq"] for e in page2] == [2, 1] and page2[-1]["event"] == "kill_switch_on"
    pid = page1[0]["proposal_id"]
    only = api.get("/audit/events", params={"proposal_id": pid}, headers=approver).json()
    assert {e["proposal_id"] for e in only} == {pid}
    assert api.get("/audit/events", params={"before_seq": 0}, headers=approver).status_code == 400
