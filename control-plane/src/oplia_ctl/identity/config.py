"""``OPLIA_IDENTITY_*`` settings, provider construction and the two entry points.

* ``oplia-jit-worker [--once]`` - every 60 s: revoke expired JIT grants; every
  ``reconcile_interval_minutes``: report (optionally remove) standing privileged memberships.
* ``oplia-identity-sweep`` - daily: propose disabling accounts inactive for 90+ days.
"""

from __future__ import annotations

import json
import logging
import signal
import threading
import time
from datetime import timedelta
from typing import Annotated, Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.http import ResilientClient
from oplia_ctl.identity.providers.base import IdentityProvider
from oplia_ctl.secrets import SecretProvider

log = logging.getLogger("oplia.identity")


class IdentitySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_IDENTITY_", extra="ignore")

    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret_name: str = "entra_client_secret"
    okta_org_url: str = ""
    okta_token_secret_name: str = "okta_api_token"
    ad_url: str = ""
    ad_bind_dn: str = ""
    ad_base_dn: str = ""
    ad_password_secret_name: str = "ad_bind_password"
    ad_ca_cert_file: str = ""
    ad_start_tls: bool = False
    catalog_path: str = ""
    standing_allowlist: dict[str, list[str]] = Field(default_factory=dict)  # "idp:group_ref" -> user ids
    remove_standing_members: bool = False
    reconcile_interval_minutes: Annotated[int, Field(ge=1, le=1440)] = 15
    worker_interval_seconds: Annotated[float, Field(ge=10, le=600)] = 60.0
    inactive_days: Annotated[int, Field(ge=30, le=3650)] = 90
    sweep_max_per_run: Annotated[int, Field(ge=1, le=10000)] = 25
    exempt_users: dict[str, list[str]] = Field(default_factory=dict)  # idp -> ids or logins (break-glass)


def build_providers(cfg: IdentitySettings, secrets: SecretProvider,
                    client: ResilientClient) -> dict[str, IdentityProvider]:
    providers: dict[str, IdentityProvider] = {}
    if cfg.entra_tenant_id:
        from oplia_ctl.identity.providers.entra import EntraProvider

        providers["entra"] = EntraProvider(tenant_id=cfg.entra_tenant_id, client_id=cfg.entra_client_id,
                                           secrets=secrets, client=client,
                                           client_secret_name=cfg.entra_client_secret_name)
    if cfg.okta_org_url:
        from oplia_ctl.identity.providers.okta import OktaProvider

        providers["okta"] = OktaProvider(org_url=cfg.okta_org_url, secrets=secrets, client=client,
                                         token_secret_name=cfg.okta_token_secret_name)
    if cfg.ad_url:
        from oplia_ctl.identity.providers.ad import AdProvider

        providers["ad"] = AdProvider(url=cfg.ad_url, bind_dn=cfg.ad_bind_dn, base_dn=cfg.ad_base_dn, secrets=secrets,
                                     password_secret_name=cfg.ad_password_secret_name,
                                     ca_cert_file=cfg.ad_ca_cert_file or None, start_tls=cfg.ad_start_tls)
    return providers


def _runtime() -> tuple[Any, Any, Any, IdentitySettings]:  # pragma: no cover - process wiring
    import oplia_ctl.identity.models  # noqa: F401
    from oplia_ctl.config import get_settings
    from oplia_ctl.db import Base, make_engine, make_session_factory
    from oplia_ctl.safety import SafetyGate

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    sf = make_session_factory(engine)
    gate = SafetyGate(sf, dry_run=settings.dry_run, require_approval=settings.require_approval,
                      four_eyes=settings.four_eyes, proposal_ttl=timedelta(minutes=settings.proposal_ttl_minutes))
    return settings, sf, gate, IdentitySettings()


def worker_main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    import argparse

    from oplia_ctl.aiops.config import AIOpsSettings, build_notifier
    from oplia_ctl.identity.jit import JitService, load_catalog
    from oplia_ctl.secrets import build_secret_provider

    p = argparse.ArgumentParser(description="Revoke expired JIT grants every 60 s; reconcile standing access.")
    p.add_argument("--once", action="store_true", help="one pass and exit")
    args = p.parse_args()
    settings, sf, gate, cfg = _runtime()
    secrets = build_secret_provider(settings.secret_provider)
    client = ResilientClient(timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries)
    providers = build_providers(cfg, secrets, client)
    svc = JitService(gate=gate, session_factory=sf, providers=providers,
                     catalog=load_catalog(cfg.catalog_path, providers),
                     notifier=build_notifier(AIOpsSettings(), secrets, client))
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    last_reconcile = 0.0
    while True:
        try:
            report: dict[str, Any] = svc.tick()
            if time.monotonic() - last_reconcile >= cfg.reconcile_interval_minutes * 60:
                report["reconcile"] = svc.reconcile(cfg.standing_allowlist, remove=cfg.remove_standing_members)
                last_reconcile = time.monotonic()
            if args.once or any(v for k, v in report.items() if k != "reconcile") or report.get("reconcile"):
                log.info("jit worker: %s", json.dumps(report, default=str))
        except Exception:  # logged and retried next tick
            log.exception("jit worker tick failed")
        if args.once or stop.wait(cfg.worker_interval_seconds):
            return


def sweep_main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    import argparse

    from oplia_ctl.aiops.config import AIOpsSettings, build_notifier
    from oplia_ctl.identity.sweep import InactivitySweeper
    from oplia_ctl.secrets import build_secret_provider

    argparse.ArgumentParser(description="Propose disabling accounts inactive for 90+ days.").parse_args()
    settings, _sf, gate, cfg = _runtime()
    secrets = build_secret_provider(settings.secret_provider)
    client = ResilientClient(timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries)
    providers = build_providers(cfg, secrets, client)
    if not providers:
        raise SystemExit("configure at least one of OPLIA_IDENTITY_ENTRA_TENANT_ID / _OKTA_ORG_URL / _AD_URL")
    report = InactivitySweeper(gate=gate, providers=providers, inactive_days=cfg.inactive_days,
                               exempt=cfg.exempt_users, max_per_run=cfg.sweep_max_per_run,
                               notifier=build_notifier(AIOpsSettings(), secrets, client)).run()
    print(json.dumps(report.as_dict(), indent=2, default=str))
    if report.errors:
        raise SystemExit(2)
