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


def test_prod_autonomous_requires_explicit_opt_in():
    Settings(environment="prod", database_url="postgresql+psycopg://u@h/db", dry_run=False,
             require_approval=False, allow_autonomous_in_prod=True, **OIDC).assert_production_safe()


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
