"""Runtime configuration.

All settings come from environment variables prefixed ``OPLIA_``. Secrets are
never configured here directly: settings only hold the *name* of a secret, which
is resolved at runtime through :mod:`oplia_ctl.secrets`.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CICDTarget(BaseModel):
    """Where a remediation is dispatched for one CI/CD system.

    Targets are fixed in configuration so that an incoming webhook can never
    point the control plane at an arbitrary repository or URL.

    This is deliberately a plain model, not a settings class: it is populated
    only through ``OPLIA_CICD__*`` variables on :class:`Settings`, so ambient
    variables such as ``GITHUB_REPOSITORY`` or ``JENKINS_URL`` (set by every
    GitHub runner and Jenkins agent) can never redirect remediation.
    """

    model_config = ConfigDict(extra="forbid")

    # GitHub
    github_api_url: str = "https://api.github.com"
    github_repository: str = ""  # "owner/repo" of the infrastructure repository
    github_event_type: str = "oplia-drift-remediation"
    github_destroy_event_type: str = "oplia-ttl-destroy"
    github_token_secret: str = "github_dispatch_token"

    # GitLab
    gitlab_url: str = "https://gitlab.com"
    gitlab_project_id: str = ""
    gitlab_ref: str = "main"
    gitlab_trigger_token_secret: str = "gitlab_trigger_token"

    # Jenkins
    jenkins_url: str = ""
    jenkins_job: str = ""  # folder path allowed, e.g. "infra/force-remediate"
    jenkins_user_secret: str = "jenkins_user"
    jenkins_api_token_secret: str = "jenkins_api_token"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_", env_nested_delimiter="__", extra="ignore")

    environment: Literal["dev", "stg", "prod"] = "dev"
    database_url: str = "sqlite:///./oplia_ctl.db"

    # Safety gate. Defaults are the safest possible: nothing mutates anything.
    dry_run: bool = True
    require_approval: bool = True
    four_eyes: bool = True  # approver must differ from requester
    proposal_ttl_minutes: int = Field(default=60, ge=1, le=7 * 24 * 60)

    # API authentication (OIDC JWT bearer tokens).
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_roles_claim: str = "roles"
    approver_role: str = "oplia-approver"
    operator_role: str = "oplia-operator"

    # Inbound webhook authentication (HMAC-SHA256 over timestamp + body).
    webhook_hmac_secret: str = "webhook_hmac_secret"
    webhook_max_skew_seconds: int = Field(default=300, ge=30, le=3600)

    # Allowed blueprints for drift remediation.
    allowed_blueprints: list[str] = ["control-tower-standard", "alz-hybrid"]

    cicd: CICDTarget = CICDTarget()

    # Outbound HTTP.
    http_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    http_max_retries: int = Field(default=3, ge=0, le=10)

    # Secrets backend.
    secret_provider: Literal["env", "vault"] = "env"

    # Explicit opt-in required before prod may run without approval and dry-run.
    allow_autonomous_in_prod: bool = False

    @field_validator("database_url")
    @classmethod
    def _not_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("database_url must not be empty")
        return v

    def assert_production_safe(self) -> None:
        """Refuse to start a prod process with dev-only settings."""
        if self.environment != "prod":
            return
        problems: list[str] = []
        if self.database_url.startswith("sqlite"):
            problems.append("OPLIA_DATABASE_URL must point to PostgreSQL in prod")
        if not (self.oidc_issuer and self.oidc_audience and self.oidc_jwks_url):
            problems.append("OIDC issuer, audience and JWKS URL are required in prod")
        if not self.require_approval and not self.dry_run and not self.allow_autonomous_in_prod:
            problems.append(
                "prod refuses autonomous mode (no approval, no dry-run) unless "
                "OPLIA_ALLOW_AUTONOMOUS_IN_PROD=true"
            )
        if self.secret_provider != "vault":  # nosec B105 - provider name, not a password
            problems.append("prod requires OPLIA_SECRET_PROVIDER=vault (environment secrets are for development)")
        else:
            from oplia_ctl.vault import VaultSettings

            vault = VaultSettings()
            if not vault.addr.startswith("https://") or vault.allow_insecure_http:
                problems.append("prod requires an https:// OPLIA_VAULT_ADDR without allow_insecure_http")
        if problems:
            raise RuntimeError("; ".join(problems))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
