"""Read-only status of every external integration, plus approver-only test notifications.

For each integration the status is one of:

* ``ok``             - configured and a harmless read-only call succeeded (detail says what was checked);
* ``configured``     - configured and its secret is present, but there is no harmless way to verify it
                       (Slack / PagerDuty / SIEM: verifying means sending - use "send test notification";
                       GitLab trigger tokens: verifying means starting a pipeline);
* ``error``          - configured but the check failed (detail = error type and message, scrubbed);
* ``not_configured`` - not set up on this control plane.

No secret value is ever returned: only whether the named secret exists. Probes are read-only:
AWS ``sts:GetCallerIdentity``, Azure / GCP / IBM token acquisition, GitHub ``GET /repos/{repo}``,
Jenkins ``GET /api/json``, Entra token, Okta ``GET /api/v1/users?limit=1``, AD LDAPS bind,
Vault login, OIDC JWKS download.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

Status = Literal["ok", "configured", "error", "not_configured"]
Category = Literal["cloud", "cicd", "identity", "alerting", "secrets", "sign-in"]


@dataclass
class Integration:
    name: str
    category: Category
    configured: bool
    target: str = ""                                  # non-secret description (repo, URL, tenant, ...)
    secrets: tuple[str, ...] = ()                     # secret NAMES that must exist
    probe: Callable[[], str] | None = None            # read-only check; returns what was verified
    notify: Callable[[str], str] | None = None        # test notification (approver only)


def _err(exc: BaseException) -> str:
    msg = f"{type(exc).__name__}: {exc}"
    for marker in ("password=", "token=", "apikey=", "secret="):
        if marker in msg.lower():
            msg = msg.split(marker, 1)[0] + marker + "<redacted>"
    return msg[:300]


class IntegrationRegistry:
    def __init__(self, items: list[Integration], secrets: SecretProvider) -> None:
        names = [i.name for i in items]
        if len(names) != len(set(names)):
            raise ValueError("integration names must be unique")
        self._items = {i.name: i for i in items}
        self._secrets = secrets

    def _missing_secrets(self, item: Integration) -> list[str]:
        missing = []
        for name in item.secrets:
            try:
                if not self._secrets.get(name):
                    missing.append(name)
            except LookupError:
                missing.append(name)
        return missing

    def replace_from(self, other: IntegrationRegistry) -> None:
        """Swap in integrations rebuilt from new settings (after a console change was applied)."""
        self._items = dict(other._items)

    def status_of(self, names: list[str]) -> list[dict[str, Any]]:
        return [r for r in self.status(names)]

    def status(self, only: list[str] | None = None) -> list[dict[str, Any]]:
        out = []
        for item in list(self._items.values()):
            if only is not None and item.name not in only:
                continue
            row: dict[str, Any] = {"name": item.name, "category": item.category, "target": item.target,
                                   "secrets": list(item.secrets), "can_test_notification": item.notify is not None
                                   and item.configured, "checked_at": datetime.now(UTC).isoformat()}
            started = time.monotonic()
            if not item.configured:
                row.update(status="not_configured", detail="not set up on this control plane")
            else:
                missing = self._missing_secrets(item)
                if missing:
                    row.update(status="error", detail=f"secret(s) missing: {', '.join(missing)}")
                elif item.probe is None:
                    row.update(status="configured",
                               detail="secret present; verified only by sending (use the test notification)"
                               if item.notify else "secret present; no read-only way to verify it")
                else:
                    try:
                        row.update(status="ok", detail=item.probe()[:300])
                    except Exception as exc:
                        row.update(status="error", detail=_err(exc))
            row["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
            out.append(row)
        return out

    def send_test(self, name: str, actor: str) -> str:
        item = self._items.get(name)
        if item is None:
            raise LookupError(name)
        if not item.configured or item.notify is None:
            raise ValueError(f"{name} does not support test notifications or is not configured")
        return item.notify(actor)


# ------------------------------------------------------------------ probes (all read-only)
def aws_probe(region: str) -> Callable[[], str]:
    def probe() -> str:
        import boto3

        ident = boto3.client("sts", region_name=region).get_caller_identity()
        return f"authenticated to AWS account {ident['Account']}"
    return probe


def azure_probe() -> str:
    from azure.identity import DefaultAzureCredential

    DefaultAzureCredential().get_token("https://management.azure.com/.default")
    return "Azure Resource Manager token acquired"


def gcp_probe() -> str:
    import google.auth
    from google.auth.transport.requests import Request

    creds, project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    creds.refresh(Request())  # type: ignore[no-untyped-call]
    return f"Google credentials valid (default project {project or 'not set'})"


def ibm_probe(secrets: SecretProvider, client: ResilientClient, key_secret: str) -> Callable[[], str]:
    def probe() -> str:
        client.request("POST", "https://iam.cloud.ibm.com/identity/token", expected={200},
                       data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                             "apikey": secrets.get(key_secret)}, headers={"Accept": "application/json"})
        return "IBM Cloud IAM token acquired"
    return probe


def github_probe(secrets: SecretProvider, client: ResilientClient, api: str, repo: str,
                 token_secret: str) -> Callable[[], str]:
    def probe() -> str:
        r = client.request("GET", f"{api.rstrip('/')}/repos/{repo}", expected={200},
                           headers={"Authorization": f"Bearer {secrets.get(token_secret)}",
                                    "Accept": "application/vnd.github+json"})
        perms = r.json().get("permissions") or {}
        return f"repository {repo} reachable (push permission: {bool(perms.get('push'))})"
    return probe


def jenkins_probe(secrets: SecretProvider, client: ResilientClient, url: str, user_secret: str,
                  token_secret: str) -> Callable[[], str]:
    def probe() -> str:
        client.request("GET", f"{url.rstrip('/')}/api/json", expected={200},
                       auth=(secrets.get(user_secret), secrets.get(token_secret)), params={"tree": "mode"})
        return "Jenkins API reachable with the configured credentials"
    return probe


def jwks_probe(client: ResilientClient, url: str) -> Callable[[], str]:
    def probe() -> str:
        keys = client.request("GET", url, expected={200}).json().get("keys") or []
        if not keys:
            raise ValueError("JWKS has no keys")
        return f"JWKS downloaded ({len(keys)} signing key(s))"
    return probe


# ------------------------------------------------------------------ test notifications
def slack_notify(channel: Any) -> Callable[[str], str]:
    def notify(actor: str) -> str:
        from oplia_ctl.aiops.notify import Incident

        channel.send(Incident(dedup_key=f"oplia-test-{uuid.uuid4()}",
                              summary=f"OPLIA test notification sent by {actor}",
                              severity="info", source="oplia-control-plane", klass="integration-test"), "opened")
        return "Slack test message sent"
    return notify


def pagerduty_notify(secrets: SecretProvider, client: ResilientClient, events_url: str,
                     key_secret: str) -> Callable[[str], str]:
    """Trigger an info-severity test event and resolve it immediately (same dedup key)."""
    def notify(actor: str) -> str:
        key = secrets.get(key_secret)
        dedup = f"oplia-test-{uuid.uuid4()}"
        client.request("POST", events_url, expected={202}, json={
            "routing_key": key, "event_action": "trigger", "dedup_key": dedup, "client": "OPLIA Control Plane",
            "payload": {"summary": f"OPLIA test notification sent by {actor} (auto-resolved)",
                        "source": "oplia-control-plane", "severity": "info", "class": "integration-test"}})
        client.request("POST", events_url, expected={202},
                       json={"routing_key": key, "event_action": "resolve", "dedup_key": dedup})
        return "PagerDuty test event triggered (severity info) and resolved"
    return notify


def siem_notify(sink: Any) -> Callable[[str], str]:
    def notify(actor: str) -> str:
        ok = sink.send({"type": "oplia.integration_test", "sent_by": actor, "time": datetime.now(UTC).isoformat()})
        if not ok:
            raise RuntimeError("SIEM did not accept the test event (written to the dead-letter file)")
        return "test event accepted by the SIEM"
    return notify


# ------------------------------------------------------------------ wiring
def build_integrations(*, settings: Any, secrets: SecretProvider, client: ResilientClient, finops_cfg: Any,
                       providers: dict[str, Any], identity_cfg: Any, aiops_cfg: Any, soar_cfg: Any,
                       siem_sink: Any | None, alerting_in_use: bool) -> IntegrationRegistry:
    """Describe every integration from the same settings the workers use (nothing configured here)."""
    from oplia_ctl.aiops.notify import SlackChannel

    c = settings.cicd
    items: list[Integration] = [
        Integration("aws", "cloud", bool(finops_cfg.aws_regions), ", ".join(finops_cfg.aws_regions),
                    probe=aws_probe(finops_cfg.aws_regions[0]) if finops_cfg.aws_regions else None),
        Integration("azure", "cloud", bool(finops_cfg.azure_subscriptions),
                    f"{len(finops_cfg.azure_subscriptions)} subscription(s)", probe=azure_probe),
        Integration("gcp", "cloud", bool(finops_cfg.gcp_scopes), ", ".join(finops_cfg.gcp_scopes), probe=gcp_probe),
        Integration("ibm", "cloud", bool(finops_cfg.ibm_account_id), finops_cfg.ibm_account_id,
                    secrets=(finops_cfg.ibm_api_key_secret,),
                    probe=ibm_probe(secrets, client, finops_cfg.ibm_api_key_secret)),
        Integration("github", "cicd", bool(c.github_repository), c.github_repository,
                    secrets=(c.github_token_secret,),
                    probe=github_probe(secrets, client, c.github_api_url, c.github_repository, c.github_token_secret)),
        Integration("gitlab", "cicd", bool(c.gitlab_project_id),
                    f"{c.gitlab_url} project {c.gitlab_project_id}" if c.gitlab_project_id else "",
                    secrets=(c.gitlab_trigger_token_secret,)),
        Integration("jenkins", "cicd", bool(c.jenkins_url and c.jenkins_job),
                    f"{c.jenkins_url} job {c.jenkins_job}" if c.jenkins_url else "",
                    secrets=(c.jenkins_user_secret, c.jenkins_api_token_secret),
                    probe=jenkins_probe(secrets, client, c.jenkins_url, c.jenkins_user_secret,
                                        c.jenkins_api_token_secret)),
        Integration("oidc-sign-in", "sign-in", bool(settings.oidc_jwks_url), settings.oidc_issuer,
                    probe=jwks_probe(client, settings.oidc_jwks_url)),
    ]
    entra, okta, ad = providers.get("entra"), providers.get("okta"), providers.get("ad")
    items += [
        Integration("entra-id", "identity", entra is not None, identity_cfg.entra_tenant_id,
                    secrets=(identity_cfg.entra_client_secret_name,),
                    probe=(lambda: (entra._bearer(), "Microsoft Graph token acquired")[1]) if entra else None),
        Integration("okta", "identity", okta is not None, identity_cfg.okta_org_url,
                    secrets=(identity_cfg.okta_token_secret_name,),
                    probe=(lambda: (okta._call("GET", "/api/v1/users", expected={200}, params={"limit": "1"}),
                                    "Okta API reachable with the token")[1]) if okta else None),
        Integration("active-directory", "identity", ad is not None, identity_cfg.ad_url,
                    secrets=(identity_cfg.ad_password_secret_name,), probe=_ad_probe(ad) if ad else None),
    ]
    slack = SlackChannel(secrets=secrets, client=client, webhook_secret=aiops_cfg.slack_webhook_secret)
    items += [
        Integration("slack", "alerting", alerting_in_use and "slack" in aiops_cfg.channels,
                    "incident webhook",
                    secrets=(aiops_cfg.slack_webhook_secret,), notify=slack_notify(slack)),
        Integration("pagerduty", "alerting", alerting_in_use and "pagerduty" in aiops_cfg.channels,
                    aiops_cfg.pagerduty_events_url,
                    secrets=(aiops_cfg.pagerduty_routing_key_secret,),
                    notify=pagerduty_notify(secrets, client, aiops_cfg.pagerduty_events_url,
                                            aiops_cfg.pagerduty_routing_key_secret)),
        Integration("siem", "alerting", siem_sink is not None, soar_cfg.siem_endpoint,
                    secrets=(soar_cfg.siem_token_secret,), notify=siem_notify(siem_sink) if siem_sink else None),
    ]
    vault_client = getattr(secrets, "client", None)
    items.append(Integration("vault", "secrets", vault_client is not None,
                             getattr(getattr(secrets, "_s", None), "addr", ""),
                             probe=(lambda: (vault_client.login(), "Vault login succeeded")[1])
                             if vault_client else None))
    return IntegrationRegistry(items, secrets)


def _ad_probe(ad: Any) -> Callable[[], str]:
    def probe() -> str:
        conn = ad._connect()
        try:
            return "LDAP bind succeeded"
        finally:
            conn.unbind_s()
    return probe
