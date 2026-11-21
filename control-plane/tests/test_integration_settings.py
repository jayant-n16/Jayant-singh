"""Integration settings edited from the console: gated, non-secret values in the DB, secrets only in Vault."""

from __future__ import annotations

import json
import os

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

import oplia_ctl.integration_settings as isettings
from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.integration_settings import (
    ACTION_INTEGRATION_SETTINGS,
    IntegrationSettingRow,
    IntegrationSettingsExecutor,
    IntegrationSettingsService,
    apply_persisted_overrides,
)
from oplia_ctl.secrets import SecretNotFoundError, StaticSecretProvider
from oplia_ctl.vault import VaultClient, VaultError, VaultSecretProvider, VaultSettings
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer
from tests.test_vault import POLICY_DIR, approle, bao, needs_vault, root  # noqa: F401 - bao is a fixture

SECRET = "xoxb-THIS-MUST-NEVER-BE-STORED-0001"  # test value whose absence is asserted


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    saved = dict(os.environ)
    for k in list(os.environ):
        if k.startswith("OPLIA_") and k != "OPLIA_TEST_DATABASE_URL" and not k.startswith("OPLIA_TEST_"):
            monkeypatch.delenv(k)
    monkeypatch.setattr(isettings, "_BASE_ENV", None)
    yield
    os.environ.clear()
    os.environ.update(saved)


class FakeKV:
    """In-memory KV v2 with the parts of the Vault API the settings service uses."""

    def __init__(self):
        self.data: dict[str, dict[str, str]] = {}
        self.versions: dict[str, int] = {}

    def write_kv(self, path, values, mount=None, cas=None):
        self.data[path] = dict(values)
        self.versions[path] = self.versions.get(path, 0) + 1
        return self.versions[path]

    def read_kv(self, path, mount=None):
        if path not in self.data:
            raise VaultError("GET", path, 404, [])
        return dict(self.data[path])

    def request(self, method, path, json=None, params=None):
        rel = path.split("/metadata/", 1)[1]
        if method == "LIST":
            prefix = rel.rstrip("/") + "/"
            keys = sorted({p[len(prefix):].split("/")[0] + ("/" if "/" in p[len(prefix):] else "")
                           for p in self.data if p.startswith(prefix)})
            if not keys:
                raise VaultError("LIST", path, 404, [])
            return {"data": {"keys": keys}}
        if method == "DELETE":
            self.data.pop(rel, None)
            return {}
        raise AssertionError(method)


class FakeVaultProvider:
    def __init__(self, kv: FakeKV):
        self.client = kv
        self._s = VaultSettings(addr="https://vault.test:8200")
        self.invalidated: list[str] = []

    def get(self, name):
        try:
            return self.client.read_kv(f"coc/{name}")["value"]
        except VaultError:
            raise SecretNotFoundError(name) from None

    def invalidate(self, name=None):
        self.invalidated.append(name)


def make(gate, session_factory, secrets, rechecked=None):
    svc = IntegrationSettingsService(session_factory, environment="dev", secrets=secrets, clock=gate.clock,
                                     recheck=lambda n: (rechecked.append(n) if rechecked is not None else None)
                                     or {"name": n, "status": "ok"})
    client = TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={ACTION_INTEGRATION_SETTINGS: IntegrationSettingsExecutor(svc)},
        webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=["control-tower-standard"], approver_role="oplia-approver",
        operator_role="oplia-operator", integration_settings=svc))
    return svc, client


ALICE, DAVE = bearer("alice", "oplia-approver"), bearer("dave", "oplia-approver")
BOB = bearer("bob", "oplia-operator")


def everything_stored(session_factory) -> str:
    """Every row of every table, as text: a secret value must not appear anywhere."""
    with session_factory() as s:
        bind = s.get_bind()
        from sqlalchemy import inspect as sa_inspect

        out = []
        for t in sa_inspect(bind).get_table_names():
            out += [repr(tuple(r)) for r in s.execute(text(f'SELECT * FROM "{t}"'))]  # noqa: S608 - table names
        return "\n".join(out)


def test_listing_shows_sources_and_secret_presence_without_values(gate, session_factory, monkeypatch):
    monkeypatch.setenv("OPLIA_FINOPS_AWS_REGIONS", '["ap-south-1"]')
    _, client = make(gate, session_factory, StaticSecretProvider({"slack_webhook_url": SECRET}))
    assert client.get("/settings/integrations", headers=BOB).status_code == 403  # approvers only
    body = client.get("/settings/integrations", headers=ALICE).json()
    assert SECRET not in json.dumps(body)
    by = {i["name"]: i for i in body["integrations"]}
    aws = by["aws"]["fields"][0]
    assert aws["value"] == ["ap-south-1"] and aws["source"] == "environment"
    assert by["github"]["fields"][1]["source"] == "default"
    assert by["slack"]["secrets"] == [{"name": "slack_webhook_url", "present": True}]
    assert by["github"]["secrets"] == [{"name": "github_dispatch_token", "present": False}]
    assert body["secrets_writable"] is False and "OPLIA_SECRET_<NAME>" in body["vault_note"]
    assert body["restart_required"] is True


def test_secrets_are_refused_without_vault_and_never_echoed(gate, session_factory):
    _, client = make(gate, session_factory, StaticSecretProvider({}))
    r = client.post("/settings/integrations/slack", headers=ALICE,
                    json={"secrets": {"slack_webhook_url": SECRET}, "reason": "rotate the Slack webhook"})
    assert r.status_code == 422 and "OPLIA_SECRET_<NAME>" in r.json()["detail"]
    assert SECRET not in r.text
    bad = client.post("/settings/integrations/slack", headers=ALICE,
                      json={"secrets": {"slack_webhook_url": 12345}, "reason": "rotate the Slack webhook"})
    assert bad.status_code == 422 and "12345" not in bad.text
    other = client.post("/settings/integrations/slack", headers=ALICE,
                        json={"secrets": {"github_dispatch_token": SECRET}, "reason": "wrong secret for slack"})
    assert other.status_code == 422 and SECRET not in other.text
    assert gate.list(None, 10) == []
    assert SECRET not in everything_stored(session_factory)


def test_validation_refuses_before_anything_is_proposed(gate, session_factory):
    _, client = make(gate, session_factory, StaticSecretProvider({}))
    cases = [
        ("github", {"values": {"OPLIA_CICD__GITHUB_API_URL": "ftp://x"}}, "must start with"),
        ("github", {"values": {"OPLIA_DATABASE_URL": "sqlite://"}}, "not an editable setting"),
        ("github", {"values": {"OPLIA_CICD__GITHUB_REPOSITORY": "a\nb"}}, "control characters"),
        ("siem", {"values": {"OPLIA_SOAR_SIEM_FORMAT": "xml"}}, "must be one of"),
        ("databases", {"values": {"OPLIA_DATABASES": [{"name": "x"}]}}, "would not load"),
        ("aws", {"values": {}}, "nothing to change"),
        ("nope", {"values": {"A": "b"}}, None),
    ]
    for name, body, msg in cases:
        r = client.post(f"/settings/integrations/{name}", headers=ALICE, json={**body, "reason": "a valid reason"})
        assert r.status_code == (404 if msg is None else 422), (name, r.text)
        if msg:
            assert msg in r.json()["detail"]
    assert client.post("/settings/integrations/aws", headers=ALICE,
                       json={"values": {"OPLIA_FINOPS_AWS_REGIONS": ["x"]}, "reason": "short"}).status_code == 422
    assert gate.list(None, 10) == []


def test_prod_safety_is_enforced_on_the_effective_configuration(gate, session_factory, monkeypatch):
    for k, v in {"OPLIA_ENVIRONMENT": "prod", "OPLIA_DATABASE_URL": "postgresql://h/db",
                 "OPLIA_OIDC_ISSUER": "https://idp", "OPLIA_OIDC_AUDIENCE": "a",
                 "OPLIA_OIDC_JWKS_URL": "https://idp/jwks", "OPLIA_SECRET_PROVIDER": "vault",
                 "OPLIA_VAULT_ADDR": "https://vault:8200"}.items():
        monkeypatch.setenv(k, v)
    _, client = make(gate, session_factory, StaticSecretProvider({}))
    r = client.post("/settings/integrations/vault", headers=ALICE,
                    json={"values": {"OPLIA_SECRET_PROVIDER": "env"}, "reason": "switch to env secrets"})
    assert r.status_code == 422 and "requires OPLIA_SECRET_PROVIDER=vault" in r.json()["detail"]


def test_gated_change_four_eyes_apply_and_precedence(gate, session_factory, monkeypatch):
    monkeypatch.setenv("OPLIA_CICD__GITHUB_REPOSITORY", "acme/old")
    rechecked: list[str] = []
    _, client = make(gate, session_factory, StaticSecretProvider({}), rechecked)
    r = client.post("/settings/integrations/github", headers=ALICE, json={
        "values": {"OPLIA_CICD__GITHUB_REPOSITORY": "acme/infra"}, "reason": "point remediation at acme/infra"})
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["status"] == "PENDING" and p["action_type"] == ACTION_INTEGRATION_SETTINGS
    assert p["payload"]["set"] == {"OPLIA_CICD__GITHUB_REPOSITORY": "acme/infra"} and p["payload"]["secret_names"] == []
    assert client.post(f"/proposals/{p['id']}/execute", headers=BOB).status_code == 409   # not approved
    assert client.post(f"/proposals/{p['id']}/approve", headers=ALICE, json={}).status_code == 403  # four eyes
    assert os.environ["OPLIA_CICD__GITHUB_REPOSITORY"] == "acme/old"  # nothing applied yet
    assert client.post(f"/proposals/{p['id']}/approve", headers=DAVE, json={}).status_code == 200
    gate.set_kill_switch(engaged=True, actor="alice", reason="incident")
    assert client.post(f"/proposals/{p['id']}/execute", headers=BOB).status_code == 423
    gate.set_kill_switch(engaged=False, actor="alice", reason="resolved")
    done = client.post(f"/proposals/{p['id']}/execute", headers=BOB).json()
    assert done["status"] == "EXECUTED", done
    assert done["result"]["applied"] == ["OPLIA_CICD__GITHUB_REPOSITORY"]
    assert done["result"]["restart_required"] is True and done["result"]["status"] == {"name": "github", "status": "ok"}
    assert rechecked == ["github"]
    assert os.environ["OPLIA_CICD__GITHUB_REPOSITORY"] == "acme/infra"
    field = next(f for i in client.get("/settings/integrations", headers=ALICE).json()["integrations"]
                 if i["name"] == "github" for f in i["fields"] if f["key"] == "OPLIA_CICD__GITHUB_REPOSITORY")
    assert field == field | {"value": "acme/infra", "source": "applied"}

    # removing the applied value falls back to the environment
    r2 = client.post("/settings/integrations/github", headers=ALICE, json={
        "values": {"OPLIA_CICD__GITHUB_REPOSITORY": None}, "reason": "revert to the configured repository"}).json()
    client.post(f"/proposals/{r2['id']}/approve", headers=DAVE, json={})
    assert client.post(f"/proposals/{r2['id']}/execute", headers=BOB).json()["result"]["removed"] == [
        "OPLIA_CICD__GITHUB_REPOSITORY"]
    assert os.environ["OPLIA_CICD__GITHUB_REPOSITORY"] == "acme/old"
    with session_factory() as s:
        assert s.execute(select(IntegrationSettingRow)).scalars().all() == []


def test_startup_applies_stored_settings_over_environment_with_break_glass(session_factory, monkeypatch, tmp_path):
    db = tmp_path / "boot.db"
    from oplia_ctl.db import Base, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    from datetime import UTC, datetime

    with make_session_factory(engine).begin() as s:
        s.add(IntegrationSettingRow(env_key="OPLIA_FINOPS_IBM_ACCOUNT_ID", value="acc-from-console",
                                    integration="ibm", change_id="c", requested_by="alice",
                                    applied_at=datetime.now(UTC)))
        s.add(IntegrationSettingRow(env_key="OPLIA_DATABASE_URL", value="sqlite:///evil",  # not editable: ignored
                                    integration="x", change_id="c", requested_by="x", applied_at=datetime.now(UTC)))
    engine.dispose()
    monkeypatch.setenv("OPLIA_FINOPS_IBM_ACCOUNT_ID", "acc-from-env")
    monkeypatch.setenv(isettings.IGNORE_ENV, "true")
    assert apply_persisted_overrides(f"sqlite:///{db}") == 0
    assert os.environ["OPLIA_FINOPS_IBM_ACCOUNT_ID"] == "acc-from-env"
    monkeypatch.delenv(isettings.IGNORE_ENV)
    assert apply_persisted_overrides(f"sqlite:///{db}") == 1
    assert os.environ["OPLIA_FINOPS_IBM_ACCOUNT_ID"] == "acc-from-console"
    assert "OPLIA_DATABASE_URL" not in os.environ or os.environ["OPLIA_DATABASE_URL"] != "sqlite:///evil"
    assert isettings.base_environment()["OPLIA_FINOPS_IBM_ACCOUNT_ID"] == "acc-from-env"
    # an empty database (tables not created yet) is not an error
    assert apply_persisted_overrides(f"sqlite:///{tmp_path / 'empty.db'}") == 0


def test_vault_secret_is_staged_then_applied_and_never_stored_or_audited(gate, session_factory):
    kv = FakeKV()
    provider = FakeVaultProvider(kv)
    _, client = make(gate, session_factory, provider)
    body = client.get("/settings/integrations", headers=ALICE).json()
    assert body["secrets_writable"] is True and body["vault_note"] == ""
    r = client.post("/settings/integrations/slack", headers=ALICE, json={
        "secrets": {"slack_webhook_url": SECRET}, "reason": "rotate the Slack incident webhook"})
    assert r.status_code == 200 and SECRET not in r.text
    p = r.json()
    cid = p["payload"]["change_id"]
    assert p["payload"]["secret_names"] == ["slack_webhook_url"]
    assert kv.data == {f"coc/_pending/{cid}/slack_webhook_url": {"value": SECRET}}  # staged in Vault only
    client.post(f"/proposals/{p['id']}/approve", headers=DAVE, json={})
    done = client.post(f"/proposals/{p['id']}/execute", headers=BOB).json()
    assert done["status"] == "EXECUTED", done
    assert done["result"]["secrets"] == [{"secret": "slack_webhook_url", "vault_version": 1}]
    assert kv.data == {"coc/slack_webhook_url": {"value": SECRET}}  # moved; staged copy destroyed
    assert provider.invalidated == ["slack_webhook_url"]
    assert SECRET not in everything_stored(session_factory)
    assert SECRET not in json.dumps(gate.list_audit(limit=50)) and SECRET not in repr(gate.list(None, 50))
    events = [e["event"] for e in gate.list_audit(limit=50)]
    assert "settings_secrets_staged" in events


def test_rejected_and_orphaned_staging_is_destroyed(gate, session_factory):
    kv = FakeKV()
    svc, client = make(gate, session_factory, FakeVaultProvider(kv))
    p = client.post("/settings/integrations/okta", headers=ALICE, json={
        "secrets": {"okta_api_token": SECRET}, "reason": "rotate the Okta API token"}).json()
    kv.write_kv("coc/_pending/orphan-id/okta_api_token", {"value": "x"})
    kv.write_kv("coc/okta_api_token", {"value": "current"})
    svc.purge_stale_staging()
    assert set(kv.data) == {f"coc/_pending/{p['payload']['change_id']}/okta_api_token", "coc/okta_api_token"}
    client.post(f"/proposals/{p['id']}/reject", headers=DAVE, json={"note": "not now"})
    client.get("/settings/integrations", headers=ALICE)  # listing purges finished proposals' staging
    assert set(kv.data) == {"coc/okta_api_token"} and kv.data["coc/okta_api_token"] == {"value": "current"}


def test_staging_failure_rejects_the_proposal_and_changes_nothing(gate, session_factory):
    kv = FakeKV()

    def broken(*a, **k):
        raise VaultError("POST", "secret/data/coc/_pending", 403, ["permission denied"])

    kv.write_kv = broken
    _, client = make(gate, session_factory, FakeVaultProvider(kv))
    r = client.post("/settings/integrations/okta", headers=ALICE, json={
        "secrets": {"okta_api_token": SECRET}, "reason": "rotate the Okta API token"})
    assert r.status_code == 502 and SECRET not in r.text
    (prop,) = gate.list(None, 5)
    assert prop.status.value == "REJECTED" and "nothing was changed" in (prop.decision_note or "")


def test_missing_staged_value_fails_without_changing_anything(gate, session_factory):
    kv = FakeKV()
    _, client = make(gate, session_factory, FakeVaultProvider(kv))
    p = client.post("/settings/integrations/okta", headers=ALICE, json={
        "values": {"OPLIA_IDENTITY_OKTA_ORG_URL": "https://acme.okta.com"},
        "secrets": {"okta_api_token": SECRET}, "reason": "connect Okta for JIT access"}).json()
    kv.data.clear()
    client.post(f"/proposals/{p['id']}/approve", headers=DAVE, json={})
    done = client.post(f"/proposals/{p['id']}/execute", headers=BOB).json()
    assert done["status"] == "FAILED" and "nothing was changed" in done["result"]["error"]
    assert "OPLIA_IDENTITY_OKTA_ORG_URL" not in os.environ
    with session_factory() as s:
        assert s.execute(select(IntegrationSettingRow)).scalars().all() == []


def test_dry_run_describes_without_values_of_secrets(gate, session_factory):
    kv = FakeKV()
    svc = IntegrationSettingsService(session_factory, environment="dev", secrets=FakeVaultProvider(kv))
    text_ = IntegrationSettingsExecutor(svc).describe({
        "integration": "okta", "set": {"OPLIA_IDENTITY_OKTA_ORG_URL": "u"}, "unset": [],
        "secret_names": ["okta_api_token"]})
    assert text_ == ("would integration okta; set OPLIA_IDENTITY_OKTA_ORG_URL=u; "
                     "write secret(s) to Vault: okta_api_token")


# ============================================================ real OpenBao
@needs_vault
def test_real_vault_staging_apply_and_policy(bao, gate, session_factory, tmp_path):  # noqa: F811 - fixture
    root("PUT", "sys/policies/acl/oplia-settings-writer",
         json={"policy": (POLICY_DIR / "oplia-settings-writer.hcl").read_text()})
    s = approle(tmp_path, "oplia-api-test", ["oplia-control-plane", "oplia-settings-writer"])
    provider = VaultSecretProvider(VaultClient(s), s)
    _, client = make(gate, session_factory, provider)
    p = client.post("/settings/integrations/siem", headers=ALICE, json={
        "secrets": {"siem_token": SECRET}, "reason": "rotate the SIEM HEC token"}).json()
    cid = p["payload"]["change_id"]
    assert root("GET", f"secret/data/coc/_pending/{cid}/siem_token")["data"]["data"] == {"value": SECRET}
    client.post(f"/proposals/{p['id']}/approve", headers=DAVE, json={})
    done = client.post(f"/proposals/{p['id']}/execute", headers=BOB).json()
    assert done["status"] == "EXECUTED", done
    assert root("GET", "secret/data/coc/siem_token")["data"]["data"] == {"value": SECRET}
    assert provider.get("siem_token") == SECRET
    r = httpx.get(f"{bao}/v1/secret/metadata/coc/_pending/{cid}/siem_token",
                  headers={"X-Vault-Token": os.environ.get("OPLIA_TEST_VAULT_ROOT_TOKEN", "")}, timeout=10)
    assert r.status_code == 404  # staged copy destroyed, all versions
    # the writer policy still cannot touch the denied root* names
    with pytest.raises(VaultError) as ei:
        provider.client.write_kv("coc/root_token", {"value": "x"})
    assert ei.value.status == 403
    # the plain control-plane policy (workers) cannot write secrets
    w = approle(tmp_path, "oplia-worker-test", ["oplia-control-plane"])
    with pytest.raises(VaultError) as ei:
        VaultClient(w).write_kv("coc/siem_token", {"value": "x"})
    assert ei.value.status == 403
    assert SECRET not in everything_stored(session_factory)
