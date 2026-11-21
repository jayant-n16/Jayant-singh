"""Integration settings edited from the console, through the safety gate.

What can be edited
    Only the NON-secret settings listed in :data:`CATALOG` (regions, repository names, URLs, tenant IDs,
    ...). Bootstrap settings - the control-plane database URL, console sign-in (OIDC), environment,
    dry-run / approval switches, Vault's KV prefix and field - are deliberately not editable here:
    a wrong value could lock everyone out or redirect where secrets are read from.

Precedence (highest first)
    1. a setting applied from the console (stored in ``integration_settings``, non-secret values only);
    2. the process environment (``OPLIA_*`` variables, the ConfigMap in Kubernetes);
    3. the built-in default.
    Applied settings are written into the process environment at API start-up, before any settings
    object is built, so every module sees the same effective value. ``OPLIA_IGNORE_APPLIED_SETTINGS=true``
    is the break-glass switch: start without them.

When a change takes effect
    Immediately in the API process that executed it (the integration status check is re-run with the
    new values and returned). Workers, CronJobs and other API replicas read settings at start-up, so
    ``restart_required`` is always true and the console says so.

Secrets (write-only, Vault only)
    A secret value is never stored in the control-plane database, never returned by the API, never
    logged and never audited by value. When the change is proposed, each value is written to Vault at
    ``<kv_mount>/data/<kv_prefix>/_pending/<change-id>/<name>``; the proposal carries only the secret
    *names* and the change id. When the approved proposal executes, the value is copied to the normal
    path ``<kv_mount>/data/<kv_prefix>/<name>`` (the existing ``secret/data/coc/<name>`` paths) and the
    staged copy is destroyed; the audit log records the name and the new Vault version. Staged values
    of proposals that were rejected, expired, failed or only dry-run are destroyed by the next listing.
    Without Vault (``OPLIA_SECRET_PROVIDER=env``, e.g. a laptop) secrets cannot be saved: the API refuses
    and explains how to set ``OPLIA_SECRET_<NAME>`` instead. There is no other fallback.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import DateTime, String, Text, delete, inspect, select
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from oplia_ctl.db import Base, make_engine, session_scope
from oplia_ctl.safety.models import ProposalRow, ProposalStatus
from oplia_ctl.secrets import _NAME_RE

ACTION_INTEGRATION_SETTINGS = "settings.integration"
IGNORE_ENV = "OPLIA_IGNORE_APPLIED_SETTINGS"
PENDING_DIR = "_pending"
MAX_BODY_BYTES = 128 * 1024
MAX_SECRET_LEN = 16 * 1024
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

Kind = Literal["text", "url", "list", "bool", "choice", "json"]


class SettingsError(ValueError):
    """A change was refused. The message never contains a secret value."""


# ---------------------------------------------------------------------------------------------- catalog
@dataclass(frozen=True)
class FieldSpec:
    env: str
    label: str
    kind: Kind = "text"
    options: tuple[str, ...] = ()
    help: str = ""


@dataclass(frozen=True)
class IntegrationSpec:
    name: str
    category: str
    fields: tuple[FieldSpec, ...]
    # (env var holding the secret NAME, default name). Secret names themselves are not editable here.
    secret_names: tuple[tuple[str, str], ...] = ()
    note: str = ""


_ALERT_CHANNELS = FieldSpec("OPLIA_AIOPS_CHANNELS", "Alert channels (pagerduty, slack)", "list",
                            help="Which channels alerting sends to. Alerting is active only when OPLIA_AIOPS_"
                                 "CLUSTER_NAME or the DR stream is set.")

CATALOG: dict[str, IntegrationSpec] = {s.name: s for s in [
    IntegrationSpec("aws", "cloud", (
        FieldSpec("OPLIA_FINOPS_AWS_REGIONS", "AWS regions", "list", help="One per line, e.g. ap-south-1"),),
        note="Credentials come from the workload identity (IRSA) or the standard AWS credential chain."),
    IntegrationSpec("azure", "cloud", (
        FieldSpec("OPLIA_FINOPS_AZURE_SUBSCRIPTIONS", "Azure subscription IDs", "list"),),
        note="Credentials come from workload identity / DefaultAzureCredential."),
    IntegrationSpec("gcp", "cloud", (
        FieldSpec("OPLIA_FINOPS_GCP_SCOPES", "GCP inventory scopes", "list",
                  help="projects/<id>, folders/<n> or organizations/<n>"),
        FieldSpec("OPLIA_FINOPS_GCP_PROJECTS", "GCP projects (idle-disk detection)", "list")),
        note="Credentials come from workload identity / Application Default Credentials."),
    IntegrationSpec("ibm", "cloud", (FieldSpec("OPLIA_FINOPS_IBM_ACCOUNT_ID", "IBM Cloud account ID"),),
                    (("OPLIA_FINOPS_IBM_API_KEY_SECRET", "ibm_cloud_api_key"),)),
    IntegrationSpec("github", "cicd", (
        FieldSpec("OPLIA_CICD__GITHUB_API_URL", "GitHub API URL", "url"),
        FieldSpec("OPLIA_CICD__GITHUB_REPOSITORY", "Repository (owner/repo)"),
        FieldSpec("OPLIA_CICD__GITHUB_EVENT_TYPE", "Remediation event type"),
        FieldSpec("OPLIA_CICD__GITHUB_DESTROY_EVENT_TYPE", "TTL destroy event type")),
        (("OPLIA_CICD__GITHUB_TOKEN_SECRET", "github_dispatch_token"),)),
    IntegrationSpec("gitlab", "cicd", (
        FieldSpec("OPLIA_CICD__GITLAB_URL", "GitLab URL", "url"),
        FieldSpec("OPLIA_CICD__GITLAB_PROJECT_ID", "Project ID"),
        FieldSpec("OPLIA_CICD__GITLAB_REF", "Branch (ref)")),
        (("OPLIA_CICD__GITLAB_TRIGGER_TOKEN_SECRET", "gitlab_trigger_token"),)),
    IntegrationSpec("jenkins", "cicd", (
        FieldSpec("OPLIA_CICD__JENKINS_URL", "Jenkins URL", "url"),
        FieldSpec("OPLIA_CICD__JENKINS_JOB", "Job path", help="Folder path allowed, e.g. infra/force-remediate")),
        (("OPLIA_CICD__JENKINS_USER_SECRET", "jenkins_user"),
         ("OPLIA_CICD__JENKINS_API_TOKEN_SECRET", "jenkins_api_token"))),
    IntegrationSpec("entra-id", "identity", (
        FieldSpec("OPLIA_IDENTITY_ENTRA_TENANT_ID", "Tenant ID"),
        FieldSpec("OPLIA_IDENTITY_ENTRA_CLIENT_ID", "Client (application) ID")),
        (("OPLIA_IDENTITY_ENTRA_CLIENT_SECRET_NAME", "entra_client_secret"),)),
    IntegrationSpec("okta", "identity", (FieldSpec("OPLIA_IDENTITY_OKTA_ORG_URL", "Okta org URL", "url"),),
                    (("OPLIA_IDENTITY_OKTA_TOKEN_SECRET_NAME", "okta_api_token"),)),
    IntegrationSpec("active-directory", "identity", (
        FieldSpec("OPLIA_IDENTITY_AD_URL", "LDAP URL", "url", help="ldaps://dc.example.com:636"),
        FieldSpec("OPLIA_IDENTITY_AD_BIND_DN", "Bind DN"),
        FieldSpec("OPLIA_IDENTITY_AD_BASE_DN", "Base DN"),
        FieldSpec("OPLIA_IDENTITY_AD_START_TLS", "Use StartTLS (for ldap://)", "bool")),
        (("OPLIA_IDENTITY_AD_PASSWORD_SECRET_NAME", "ad_bind_password"),)),
    IntegrationSpec("slack", "alerting", (_ALERT_CHANNELS,),
                    (("OPLIA_AIOPS_SLACK_WEBHOOK_SECRET", "slack_webhook_url"),)),
    IntegrationSpec("pagerduty", "alerting", (
        _ALERT_CHANNELS, FieldSpec("OPLIA_AIOPS_PAGERDUTY_EVENTS_URL", "Events API URL", "url")),
        (("OPLIA_AIOPS_PAGERDUTY_ROUTING_KEY_SECRET", "pagerduty_routing_key"),)),
    IntegrationSpec("siem", "alerting", (
        FieldSpec("OPLIA_SOAR_SIEM_ENDPOINT", "SIEM endpoint", "url"),
        FieldSpec("OPLIA_SOAR_SIEM_FORMAT", "Format", "choice", ("generic", "splunk_hec"))),
        (("OPLIA_SOAR_SIEM_TOKEN_SECRET", "siem_token"),)),
    IntegrationSpec("vault", "secrets", (
        FieldSpec("OPLIA_SECRET_PROVIDER", "Secret provider", "choice", ("env", "vault"),
                  help="prod refuses anything but vault"),
        FieldSpec("OPLIA_VAULT_ADDR", "Vault address", "url"),
        FieldSpec("OPLIA_VAULT_NAMESPACE", "Namespace (Enterprise / HCP)"),
        FieldSpec("OPLIA_VAULT_AUTH_METHOD", "Auth method", "choice", ("kubernetes", "approle")),
        FieldSpec("OPLIA_VAULT_KUBERNETES_MOUNT", "Kubernetes auth mount"),
        FieldSpec("OPLIA_VAULT_KUBERNETES_ROLE", "Kubernetes auth role"),
        FieldSpec("OPLIA_VAULT_APPROLE_MOUNT", "AppRole mount"),
        FieldSpec("OPLIA_VAULT_KV_MOUNT", "KV v2 mount")),
        note="The KV prefix (coc) and field are fixed: changing them would move every secret path."),
    IntegrationSpec("databases", "databases", (
        FieldSpec("OPLIA_DATABASES", "Databases (JSON list)", "json",
                  help="Same format as OPLIA_DATABASES; each entry names its DSN secret in dsn_secret"),),
        note="DSN secrets are the dsn_secret names of the entries."),
]}

_ALL_KEYS = {f.env for s in CATALOG.values() for f in s.fields}


# ---------------------------------------------------------------------------------------------- storage
class IntegrationSettingRow(Base):
    """One applied, non-secret setting. Never holds a secret value."""

    __tablename__ = "integration_settings"

    env_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    integration: Mapped[str] = mapped_column(String(64), index=True)
    change_id: Mapped[str] = mapped_column(String(36))
    requested_by: Mapped[str] = mapped_column(String(256))
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


_ENV_LOCK = threading.RLock()
# The environment as the process started, before applied settings were written into it.
_BASE_ENV: dict[str, str] | None = None


def base_environment() -> dict[str, str]:
    return dict(_BASE_ENV) if _BASE_ENV is not None else dict(os.environ)


def load_applied(sf: sessionmaker[Session]) -> dict[str, str]:
    with session_scope(sf) as s:
        bind = s.get_bind()
        if not inspect(bind).has_table(IntegrationSettingRow.__tablename__):
            return {}
        return {r.env_key: r.value for r in s.execute(select(IntegrationSettingRow)).scalars()
                if r.env_key in _ALL_KEYS}


def apply_persisted_overrides(database_url: str) -> int:
    """Called once at API start-up, before settings are built. Returns how many settings were applied."""
    global _BASE_ENV
    with _ENV_LOCK:
        if _BASE_ENV is None:
            _BASE_ENV = dict(os.environ)
        if os.environ.get(IGNORE_ENV, "").lower() in ("1", "true", "yes"):
            return 0
        engine = make_engine(database_url)
        try:
            applied = load_applied(sessionmaker(bind=engine))
        finally:
            engine.dispose()
        os.environ.update(applied)
        return len(applied)


@contextmanager
def _environment(env: dict[str, str]) -> Iterator[None]:
    """Temporarily replace the process environment (under a lock) to validate a candidate configuration."""
    with _ENV_LOCK:
        saved = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update(env)
            yield
        finally:
            os.environ.clear()
            os.environ.update(saved)


# ------------------------------------------------------------------------------------- value handling
def _encode(spec: FieldSpec, value: Any, *, dev: bool) -> str:
    """Validate a submitted value and encode it as the environment string pydantic-settings parses."""
    def text(v: Any, what: str) -> str:
        if not isinstance(v, str):
            raise SettingsError(f"{what}: must be text")
        out = str(v).strip()
        if len(out) > 512 or _CTRL.search(out):
            raise SettingsError(f"{what}: at most 512 characters, no line breaks or control characters")
        return out

    if spec.kind == "bool":
        if not isinstance(value, bool):
            raise SettingsError(f"{spec.label}: must be true or false")
        return "true" if value else "false"
    if spec.kind == "list":
        if not isinstance(value, list) or len(value) > 100:
            raise SettingsError(f"{spec.label}: must be a list of at most 100 entries")
        items = [text(v, spec.label) for v in value]
        if any(not i for i in items):
            raise SettingsError(f"{spec.label}: empty entries are not allowed")
        return json.dumps(items)
    if spec.kind == "json":
        encoded = json.dumps(value, separators=(",", ":"))
        if len(encoded) > 64 * 1024:
            raise SettingsError(f"{spec.label}: larger than 64 KiB")
        return encoded
    v = text(value, spec.label)
    if spec.kind == "choice" and v not in spec.options:
        raise SettingsError(f"{spec.label}: must be one of {', '.join(spec.options)}")
    if spec.kind == "url" and v:
        schemes = ("https://", "ldaps://") + (("http://", "ldap://") if dev else ())
        if not v.startswith(schemes):
            raise SettingsError(f"{spec.label}: must start with {' or '.join(schemes)}")
    return v


def _decode(spec: FieldSpec, raw: str | None) -> Any:
    if raw is None:
        return None
    if spec.kind == "bool":
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if spec.kind in ("list", "json"):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return [p.strip() for p in raw.split(",") if p.strip()] if spec.kind == "list" else raw
    return raw


def _validate_configuration(env: dict[str, str]) -> None:
    """Build every settings object from a candidate environment; refuse anything that would not start."""
    from pydantic import ValidationError

    from oplia_ctl.aiops.config import AIOpsSettings
    from oplia_ctl.config import Settings
    from oplia_ctl.databases.config import DatabaseSettings
    from oplia_ctl.finops.config import FinOpsSettings
    from oplia_ctl.identity.config import IdentitySettings
    from oplia_ctl.soar.exporter import SOARSettings
    from oplia_ctl.vault import VaultSettings

    with _environment(env):
        try:
            settings = Settings()
            for cls in (FinOpsSettings, IdentitySettings, AIOpsSettings, SOARSettings, DatabaseSettings, VaultSettings):
                cls()
            settings.assert_production_safe()
        except ValidationError as exc:
            msgs = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
            raise SettingsError("the configuration would not load: " + "; ".join(msgs)[:600]) from None
        except RuntimeError as exc:
            raise SettingsError(f"refused: {exc}"[:600]) from None


# --------------------------------------------------------------------------------------------- service
@dataclass
class ParsedChange:
    integration: str
    values: dict[str, str | None]          # env key -> encoded value, None = remove the applied setting
    secrets: dict[str, str] = field(repr=False)  # name -> value (never stored, never logged)
    reason: str = ""


class IntegrationSettingsService:
    def __init__(self, sf: sessionmaker[Session], *, environment: str, secrets: Any,
                 recheck: Callable[[str], dict[str, Any] | None] | None = None,
                 on_applied: Callable[[], None] | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._sf = sf
        self._clock = clock
        self._dev = environment == "dev"
        self._secrets = secrets
        self._recheck = recheck
        self._on_applied = on_applied

    # ----------------------------------------------------------------- vault
    @property
    def _vault(self) -> Any | None:
        """The Vault client and settings when secrets live in Vault; None otherwise."""
        client = getattr(self._secrets, "client", None)
        s = getattr(self._secrets, "_s", None)
        if client is None or s is None or not hasattr(client, "write_kv"):
            return None
        return client

    def _vs(self) -> Any:
        return self._secrets._s  # VaultSettings of the provider

    def vault_note(self) -> str:
        if self._vault is not None:
            return ""
        return ("Secrets cannot be saved from the console: this control plane does not use Vault "
                "(OPLIA_SECRET_PROVIDER=env). Set each secret as an environment variable named "
                "OPLIA_SECRET_<NAME> (upper case, e.g. OPLIA_SECRET_SLACK_WEBHOOK_URL) for the API and "
                "workers, then restart them.")

    # ------------------------------------------------------------- reading
    def _applied(self) -> dict[str, str]:
        return load_applied(self._sf)

    def _effective_env(self, applied: dict[str, str] | None = None) -> dict[str, str]:
        env = base_environment()
        env.update(self._applied() if applied is None else applied)
        return env

    def secret_names(self, name: str, env: dict[str, str] | None = None) -> list[str]:
        spec = CATALOG[name]
        env = self._effective_env() if env is None else env
        if name == "databases":
            raw = env.get("OPLIA_DATABASES")
            try:
                entries = json.loads(raw) if raw else []
            except json.JSONDecodeError:
                entries = []
            return sorted({str(e.get("dsn_secret")) for e in entries if isinstance(e, dict) and e.get("dsn_secret")})
        return [env.get(k) or default for k, default in spec.secret_names]

    def _present(self, secret: str) -> bool:
        try:
            return bool(self._secrets.get(secret))
        except Exception:  # missing, invalid name or backend error: not usable
            return False

    def describe_all(self) -> dict[str, Any]:
        self.purge_stale_staging()
        applied = self._applied()
        base = base_environment()
        env = self._effective_env(applied)
        out = []
        for spec in CATALOG.values():
            fields = []
            for f in spec.fields:
                if f.env in applied:
                    raw, source = applied[f.env], "applied"
                elif f.env in base:
                    raw, source = base[f.env], "environment"
                else:
                    raw, source = None, "default"
                fields.append({"key": f.env, "label": f.label, "kind": f.kind, "options": list(f.options),
                               "help": f.help, "value": _decode(f, raw), "source": source})
            present = [{"name": n, "present": self._present(n)} for n in self.secret_names(spec.name, env)]
            out.append({"name": spec.name, "category": spec.category, "note": spec.note, "fields": fields,
                        "secrets": present})
        return {"integrations": out, "secrets_writable": self._vault is not None, "vault_note": self.vault_note(),
                "restart_required": True,
                "precedence": "applied in the console > environment variable > built-in default"}

    # ------------------------------------------------------------- parsing
    def parse(self, name: str, body: Any) -> ParsedChange:
        """Validate a request body. Error messages name fields, never echo secret values."""
        spec = CATALOG.get(name)
        if spec is None:
            raise LookupError(name)
        if not isinstance(body, dict):
            raise SettingsError("body must be a JSON object")
        unknown = set(body) - {"values", "secrets", "reason"}
        if unknown:
            raise SettingsError(f"unknown field(s): {', '.join(sorted(unknown))}")
        reason = body.get("reason")
        if not isinstance(reason, str) or not (10 <= len(reason.strip()) <= 1000):
            raise SettingsError("reason: 10 to 1000 characters")
        values_in = body.get("values") or {}
        secrets_in = body.get("secrets") or {}
        if not isinstance(values_in, dict) or not isinstance(secrets_in, dict):
            raise SettingsError("values and secrets must be objects")
        fields = {f.env: f for f in spec.fields}
        values: dict[str, str | None] = {}
        for key, v in values_in.items():
            if key not in fields:
                raise SettingsError(f"{key} is not an editable setting of {name}")
            values[key] = None if v is None else _encode(fields[key], v, dev=self._dev)
        allowed = set(self.secret_names(name, self._candidate_env(values)))
        secrets: dict[str, str] = {}
        for sname, v in secrets_in.items():
            if not isinstance(sname, str) or not _NAME_RE.fullmatch(sname) or sname not in allowed:
                raise SettingsError(f"secret {sname!r} is not a secret of {name} "
                                    f"(allowed: {', '.join(sorted(allowed)) or 'none'})")
            if not isinstance(v, str) or not v.strip() or len(v) > MAX_SECRET_LEN or "\x00" in v:
                raise SettingsError(f"secret {sname}: must be non-empty text up to {MAX_SECRET_LEN} characters")
            secrets[sname] = v
        if not values and not secrets:
            raise SettingsError("nothing to change")
        if secrets and self._vault is None:
            raise SettingsError(self.vault_note())
        _validate_configuration(self._candidate_env(values))
        return ParsedChange(name, values, secrets, reason.strip())

    def _candidate_env(self, values: dict[str, str | None]) -> dict[str, str]:
        applied = self._applied()
        for k, v in values.items():
            if v is None:
                applied.pop(k, None)
            else:
                applied[k] = v
        return self._effective_env(applied)

    # ------------------------------------------------------------- proposing
    def payload(self, change: ParsedChange, change_id: str, requested_by: str) -> dict[str, Any]:
        return {"integration": change.integration, "change_id": change_id, "requested_by": requested_by,
                "set": {k: v for k, v in change.values.items() if v is not None},
                "unset": sorted(k for k, v in change.values.items() if v is None),
                "secret_names": sorted(change.secrets)}

    def _pending_path(self, change_id: str, name: str = "") -> str:
        p = f"{self._vs().kv_prefix}/{PENDING_DIR}/{change_id}"
        return f"{p}/{name}" if name else p

    def stage_secrets(self, change_id: str, secrets: dict[str, str]) -> None:
        client = self._vault
        if client is None:
            raise SettingsError(self.vault_note())
        field_name = self._vs().kv_field
        for name, value in secrets.items():
            client.write_kv(self._pending_path(change_id, name), {field_name: value})

    def destroy_staging(self, change_id: str) -> None:
        client = self._vault
        if client is None:
            return
        from urllib.parse import quote

        from oplia_ctl.vault import VaultError

        mount = self._vs().kv_mount
        try:
            listed = client.request("LIST", f"/v1/{quote(mount)}/metadata/{quote(self._pending_path(change_id))}/")
            names = [k for k in (listed.get("data") or {}).get("keys", []) if not k.endswith("/")]
        except VaultError as exc:
            if exc.status == 404:
                return
            raise
        for n in names:
            client.request("DELETE", f"/v1/{quote(mount)}/metadata/{quote(self._pending_path(change_id, n))}")

    def purge_stale_staging(self) -> int:
        """Destroy staged secrets whose proposal is finished without applying them, or that have no proposal."""
        client = self._vault
        if client is None:
            return 0
        from urllib.parse import quote

        from oplia_ctl.vault import VaultError

        try:
            listed = client.request(
                "LIST", f"/v1/{quote(self._vs().kv_mount)}/metadata/{quote(self._vs().kv_prefix)}/{PENDING_DIR}/")
        except VaultError as exc:
            if exc.status == 404:
                return 0
            raise
        change_ids = [k.rstrip("/") for k in (listed.get("data") or {}).get("keys", []) if k.endswith("/")]
        if not change_ids:
            return 0
        live: set[str] = set()
        now = self._clock()
        with session_scope(self._sf) as s:
            rows = s.execute(select(ProposalRow).where(
                ProposalRow.action_type == ACTION_INTEGRATION_SETTINGS)).scalars()
            for r in rows:
                cid = json.loads(r.payload_json).get("change_id")
                expires = r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=UTC)
                waiting = r.status in (ProposalStatus.PENDING.value, ProposalStatus.APPROVED.value) and expires > now
                if r.status == ProposalStatus.EXECUTING.value or waiting:
                    live.add(cid)
        purged = 0
        for cid in change_ids:
            if cid not in live:
                self.destroy_staging(cid)
                purged += 1
        return purged

    # ------------------------------------------------------------- applying
    def apply(self, payload: dict[str, Any]) -> dict[str, Any]:
        name = payload["integration"]
        if name not in CATALOG:
            raise SettingsError(f"unknown integration {name}")
        keys = {f.env for f in CATALOG[name].fields}
        sets: dict[str, str] = payload.get("set") or {}
        unsets: list[str] = payload.get("unset") or []
        if not set(sets) | set(unsets) <= keys:
            raise SettingsError("payload names a setting that is not editable for this integration")
        values: dict[str, str | None] = {**sets, **{k: None for k in unsets}}
        # validated again: other settings may have changed since the proposal was made
        _validate_configuration(self._candidate_env(values))
        change_id = payload["change_id"]
        secret_names: list[str] = payload.get("secret_names") or []
        written: list[dict[str, Any]] = []
        if secret_names:
            client = self._vault
            if client is None:
                raise SettingsError(self.vault_note())
            vs = self._vs()
            staged: dict[str, str] = {}
            from oplia_ctl.vault import VaultError

            for n in secret_names:  # read all first: nothing is changed unless every value is staged
                try:
                    v = client.read_kv(self._pending_path(change_id, n)).get(vs.kv_field)
                except VaultError as exc:
                    if exc.status != 404:
                        raise
                    v = None
                if not isinstance(v, str) or not v:
                    raise SettingsError(f"staged value for secret {n} is missing in Vault; nothing was changed")
                staged[n] = v
            for n, v in staged.items():
                version = client.write_kv(f"{vs.kv_prefix}/{n}", {vs.kv_field: v})
                written.append({"secret": n, "vault_version": version})
                invalidate = getattr(self._secrets, "invalidate", None)
                if invalidate is not None:
                    invalidate(n)
            staged.clear()
            self.destroy_staging(change_id)
        now = datetime.now(UTC)
        with session_scope(self._sf) as s:
            for k in unsets:
                s.execute(delete(IntegrationSettingRow).where(IntegrationSettingRow.env_key == k))
            for k, v in sets.items():
                row = s.get(IntegrationSettingRow, k)
                if row is None:
                    s.add(IntegrationSettingRow(env_key=k, value=v, integration=name, change_id=change_id,
                                                requested_by=str(payload.get("requested_by", "")), applied_at=now))
                else:
                    row.value, row.integration, row.change_id = v, name, change_id
                    row.requested_by, row.applied_at = str(payload.get("requested_by", "")), now
        global _BASE_ENV
        with _ENV_LOCK:  # this API process uses the new values immediately
            if _BASE_ENV is None:  # first change in a process started without apply_persisted_overrides
                _BASE_ENV = dict(os.environ)
            base = base_environment()
            for k in unsets:
                if k in base:
                    os.environ[k] = base[k]
                else:
                    os.environ.pop(k, None)
            os.environ.update(sets)
        if self._on_applied is not None:
            self._on_applied()
        status = self._recheck(name) if self._recheck is not None else None
        return {"integration": name, "applied": sorted(sets), "removed": sorted(unsets), "secrets": written,
                "restart_required": True,
                "restart_note": "workers, CronJobs and other API replicas use the new settings after a restart",
                "status": status}


class IntegrationSettingsExecutor:
    """Safety-gate executor for ``settings.integration`` proposals."""

    def __init__(self, service: IntegrationSettingsService) -> None:
        self._svc = service

    def describe(self, payload: dict[str, Any]) -> str:
        parts = [f"integration {payload.get('integration')}"]
        if payload.get("set"):
            parts.append("set " + ", ".join(f"{k}={v}" for k, v in sorted(payload["set"].items())))
        if payload.get("unset"):
            parts.append("remove applied " + ", ".join(payload["unset"]))
        if payload.get("secret_names"):
            parts.append("write secret(s) to Vault: " + ", ".join(payload["secret_names"]))
        return "would " + "; ".join(parts)

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._svc.apply(payload)


def new_change_id() -> str:
    return str(uuid.uuid4())
