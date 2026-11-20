from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from oplia_ctl.config import Settings
from oplia_ctl.main import build

OIDC = {"oidc_issuer": "https://idp.example.com/", "oidc_audience": "oplia-api",
        "oidc_jwks_url": "https://idp.example.com/jwks"}


def test_build_dev_app_and_health(tmp_path):
    app = build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'w.db'}", **OIDC))
    client = TestClient(app)
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    assert client.get("/proposals").status_code == 401  # auth enforced in the real wiring


def test_defaults_are_safe():
    s = Settings()
    assert s.dry_run is True and s.require_approval is True and s.four_eyes is True


@pytest.mark.parametrize("over,msg", [
    ({"database_url": "sqlite:///x.db"}, "PostgreSQL"),
    ({"oidc_issuer": ""}, "OIDC"),
    ({"dry_run": False, "require_approval": False}, "autonomous"),
])
def test_prod_refuses_unsafe_settings(over, msg):
    base = {"environment": "prod", "database_url": "postgresql+psycopg://u@h/db", **OIDC}
    with pytest.raises(RuntimeError, match=msg):
        Settings(**(base | over)).assert_production_safe()


def test_prod_autonomous_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("OPLIA_VAULT_ADDR", "https://vault.example.com:8200")
    Settings(environment="prod", database_url="postgresql+psycopg://u@h/db", dry_run=False,
             require_approval=False, allow_autonomous_in_prod=True, secret_provider="vault",
             **OIDC).assert_production_safe()


def test_prod_requires_vault_over_https(monkeypatch):
    base = {"environment": "prod", "database_url": "postgresql+psycopg://u@h/db", **OIDC}
    with pytest.raises(RuntimeError, match="OPLIA_SECRET_PROVIDER=vault"):
        Settings(**base).assert_production_safe()
    monkeypatch.setenv("OPLIA_VAULT_ADDR", "http://vault:8200")
    with pytest.raises(RuntimeError, match="https"):
        Settings(**base, secret_provider="vault").assert_production_safe()
    monkeypatch.setenv("OPLIA_VAULT_ADDR", "https://vault:8200")
    monkeypatch.setenv("OPLIA_VAULT_ALLOW_INSECURE_HTTP", "true")
    with pytest.raises(RuntimeError, match="allow_insecure_http"):
        Settings(**base, secret_provider="vault").assert_production_safe()


def test_ambient_ci_variables_cannot_redirect_remediation(monkeypatch):
    # Regression: GitHub runners set GITHUB_REPOSITORY and Jenkins agents set JENKINS_URL.
    # These must never populate the remediation target; only OPLIA_CICD__* may.
    monkeypatch.setenv("GITHUB_REPOSITORY", "attacker/repo")
    monkeypatch.setenv("JENKINS_URL", "https://evil.example.com")
    monkeypatch.setenv("GITLAB_PROJECT_ID", "999")
    s = Settings()
    assert s.cicd.github_repository == ""
    assert s.cicd.jenkins_url == ""
    assert s.cicd.gitlab_project_id == ""
    monkeypatch.setenv("OPLIA_CICD__GITHUB_REPOSITORY", "acme/infra")
    assert Settings().cicd.github_repository == "acme/infra"


def test_build_with_aiops_enabled(tmp_path, monkeypatch):
    import json

    from oplia_ctl.aiops.matrix import DEFAULT_MATRIX

    rb = [{"id": i, "description": "d", "image": f"r.example.com/x@sha256:{'b' * 64}", "command": ["true"],
           "allowed_namespaces": ["shop"]} for i in ("db-connection-pool-flush", "memory-cache-clear", "iops-optimize")]
    (tmp_path / "rb.json").write_text(json.dumps(rb))
    monkeypatch.setenv("OPLIA_AIOPS_CLUSTER_NAME", "prod-eks-1")
    monkeypatch.setenv("OPLIA_AIOPS_RUNBOOKS_PATH", str(tmp_path / "rb.json"))
    monkeypatch.setenv("OPLIA_AIOPS_ESCALATION_POLICY", json.dumps({
        s: {"lead_minutes": 30, "channels": ["slack"], "min_probability": 0.5}
        for s in ("critical", "high", "medium", "low")}))
    app = build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'a.db'}", **OIDC))
    client = TestClient(app)
    assert client.get("/aiops/predictions").status_code == 401  # route exists, auth enforced
    assert len(DEFAULT_MATRIX) == 8


def test_build_with_aiops_but_missing_runbooks_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("OPLIA_AIOPS_CLUSTER_NAME", "prod-eks-1")
    with pytest.raises(ValueError, match="unregistered runbooks"):
        build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'b.db'}", **OIDC))


def test_build_registers_finops(tmp_path, monkeypatch):
    import json

    monkeypatch.setenv("OPLIA_FINOPS_MAINTENANCE_WINDOWS",
                       json.dumps([{"days": ["sat"], "start": "02:00", "end": "06:00", "tz": "Asia/Kolkata"}]))
    monkeypatch.setenv("OPLIA_FINOPS_POLICY", json.dumps({"allowed_environments": ["dev", "stg", "prod"]}))
    from oplia_ctl.finops.config import FinOpsSettings

    cfg = FinOpsSettings()
    assert cfg.maintenance_windows[0].tz == "Asia/Kolkata"
    assert cfg.policy.required == ["Owner", "CostCenter", "Environment"]
    assert cfg.policy.allowed_environments == ["dev", "stg", "prod"]
    app = build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'f.db'}", **OIDC))
    assert TestClient(app).get("/finops/findings").status_code == 401  # route exists, auth enforced


def test_build_with_identity_providers_and_catalog(tmp_path, monkeypatch):
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "examples" / "identity" / "jit-roles.example.json"
    monkeypatch.setenv("OPLIA_IDENTITY_ENTRA_TENANT_ID", "11111111-1111-1111-1111-111111111111")
    monkeypatch.setenv("OPLIA_IDENTITY_ENTRA_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
    monkeypatch.setenv("OPLIA_IDENTITY_OKTA_ORG_URL", "https://acme.okta.com")
    monkeypatch.setenv("OPLIA_IDENTITY_AD_URL", "ldaps://dc1.corp.example.com")
    monkeypatch.setenv("OPLIA_IDENTITY_AD_BIND_DN", "CN=svc-oplia,OU=Service Accounts,DC=corp,DC=example,DC=com")
    monkeypatch.setenv("OPLIA_IDENTITY_AD_BASE_DN", "DC=corp,DC=example,DC=com")
    monkeypatch.setenv("OPLIA_IDENTITY_CATALOG_PATH", str(example))
    app = build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'i.db'}", **OIDC))
    assert TestClient(app).get("/jit/roles").status_code == 401  # route exists and is protected


def test_build_identity_catalog_with_missing_provider_fails(tmp_path, monkeypatch):
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "examples" / "identity" / "jit-roles.example.json"
    monkeypatch.setenv("OPLIA_IDENTITY_CATALOG_PATH", str(example))
    with pytest.raises(ValueError, match="not configured"):
        build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'j.db'}", **OIDC))


def test_build_with_dr_breaker(tmp_path, monkeypatch):
    import json

    monkeypatch.setenv("OPLIA_DR_STREAM", "orders-pg")
    monkeypatch.setenv("OPLIA_DR_TARGETS", json.dumps([
        {"name": "dr-azure-pg", "engine": "postgres", "cloud": "azure", "dsn_secret": "d1", "database": "orders"},
        {"name": "dr-gcp-mysql", "engine": "mysql", "cloud": "gcp", "dsn_secret": "d2"}]))
    monkeypatch.setenv("OPLIA_DR_QUARANTINE_DIR", str(tmp_path / "q"))
    app = build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'dr.db'}", **OIDC))
    assert TestClient(app).get("/dr/breakers").status_code == 401  # route exists, protected


def test_dr_target_names_must_be_unique(tmp_path, monkeypatch):
    import json

    monkeypatch.setenv("OPLIA_DR_STREAM", "orders-pg")
    t = {"name": "dr-1", "engine": "mysql", "cloud": "gcp", "dsn_secret": "d"}
    monkeypatch.setenv("OPLIA_DR_TARGETS", json.dumps([t, t]))
    with pytest.raises(ValueError, match="unique"):
        build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'd2.db'}", **OIDC))


def test_execute_with_unconfigured_cicd_fails_cleanly(tmp_path, monkeypatch):
    # Regression for the dev set-up: no GitHub/GitLab/Jenkins target configured.
    import json
    import time

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from oplia_ctl.auth import sign_webhook

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class _Key:  # stands in for the JWKS lookup; the token signature is still verified
        def __init__(self, k):
            self.key = k

    monkeypatch.setattr(jwt.PyJWKClient, "get_signing_key_from_jwt", lambda self, token: _Key(key.public_key()))
    monkeypatch.setenv("OPLIA_SECRET_WEBHOOK_HMAC_SECRET", "s3cret")
    app = build(Settings(environment="dev", database_url=f"sqlite:///{tmp_path / 'x.db'}", **OIDC))
    client = TestClient(app)

    def bearer(user, *roles):
        now = int(time.time())
        tok = jwt.encode({"iss": OIDC["oidc_issuer"], "aud": OIDC["oidc_audience"], "sub": user, "roles": list(roles),
                          "iat": now, "exp": now + 300}, key, algorithm="RS256")
        return {"Authorization": f"Bearer {tok}"}

    body = json.dumps({"zone_name": "z1", "cloud": "aws", "account_id": "111122223333",
                       "blueprint": "control-tower-standard", "target_cicd": "github"}).encode()
    ts = str(int(time.time()))
    p = client.post("/webhooks/drift", content=body, headers={
        "Content-Type": "application/json", "X-OPLIA-Timestamp": ts, "X-OPLIA-Delivery": "d-1",
        "X-OPLIA-Signature": sign_webhook("s3cret", ts, body)}).json()
    approved = client.post(f"/proposals/{p['id']}/approve", json={}, headers=bearer("alice", "oplia-approver"))
    assert approved.status_code == 200
    r = client.post(f"/proposals/{p['id']}/execute", headers=bearer("bob", "oplia-operator"))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "FAILED"
    assert r.json()["result"]["error_type"] == "CICDNotConfiguredError"
