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
