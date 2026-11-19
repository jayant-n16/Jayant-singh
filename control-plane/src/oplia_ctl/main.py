"""ASGI entrypoint: ``uvicorn oplia_ctl.main:app``."""

from __future__ import annotations

import logging
from datetime import timedelta

from fastapi import FastAPI

from oplia_ctl.api import create_app, sqlalchemy_ping
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.cloud.aws_isolation import AwsInstanceIsolationExecutor
from oplia_ctl.cloud.azure_isolation import AzureNicIsolationExecutor
from oplia_ctl.cloud.k8s_isolation import K8sNamespaceIsolationExecutor
from oplia_ctl.config import Settings, get_settings
from oplia_ctl.db import Base, make_engine, make_session_factory
from oplia_ctl.drivers.cicd import build_cicd_driver
from oplia_ctl.http import ResilientClient
from oplia_ctl.lifecycle.manager import ACTION_IAC_DESTROY
from oplia_ctl.remediation.drift import ACTION_DRIFT_REMEDIATE, PipelineDispatchExecutor
from oplia_ctl.safety import Executor, SafetyGate
from oplia_ctl.secrets import build_secret_provider
from oplia_ctl.soar.exporter import SOARExporter, SOARSettings
from oplia_ctl.soar.siem import SIEMSink


def build(settings: Settings) -> FastAPI:
    settings.assert_production_safe()
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)  # stg/prod use migrations
    gate = SafetyGate(
        make_session_factory(engine),
        dry_run=settings.dry_run,
        require_approval=settings.require_approval,
        four_eyes=settings.four_eyes,
        proposal_ttl=timedelta(minutes=settings.proposal_ttl_minutes),
    )
    secrets = build_secret_provider(settings.secret_provider)
    client = ResilientClient(timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries)
    pipeline_dispatch = PipelineDispatchExecutor(
        lambda name: build_cicd_driver(name, settings.cicd, secrets, client)
    )
    executors: dict[str, Executor] = {
        ACTION_DRIFT_REMEDIATE: pipeline_dispatch,
        ACTION_IAC_DESTROY: pipeline_dispatch,
        "isolate.aws": AwsInstanceIsolationExecutor(),
        "isolate.azure": AzureNicIsolationExecutor(),
        "isolate.k8s": K8sNamespaceIsolationExecutor(),
    }
    soar_cfg = SOARSettings()
    soar_exporter = None
    if soar_cfg.siem_endpoint:
        sink = SIEMSink(endpoint=soar_cfg.siem_endpoint, fmt=soar_cfg.siem_format,
                        token_secret=soar_cfg.siem_token_secret, secrets=secrets, client=client,
                        dead_letter_path=soar_cfg.dead_letter_path)
        soar_exporter = SOARExporter(gate=gate, sink=sink, threshold=soar_cfg.threshold)
    verifier = OIDCVerifier(issuer=settings.oidc_issuer, audience=settings.oidc_audience,
                            jwks_url=settings.oidc_jwks_url, roles_claim=settings.oidc_roles_claim)
    logging.getLogger("oplia").info("control plane starting: env=%s dry_run=%s require_approval=%s",
                                    settings.environment, settings.dry_run, settings.require_approval)
    return create_app(
        gate=gate,
        secrets=secrets,
        verifier=verifier,
        executors=executors,
        webhook_secret_name=settings.webhook_hmac_secret,
        webhook_max_skew_seconds=settings.webhook_max_skew_seconds,
        allowed_blueprints=settings.allowed_blueprints,
        approver_role=settings.approver_role,
        operator_role=settings.operator_role,
        soar_exporter=soar_exporter,
        db_ping=sqlalchemy_ping(engine),
    )


def __getattr__(name: str) -> FastAPI:
    # Lazy so importing this module (e.g. in tests or tooling) does not read env or open the DB.
    if name == "app":
        return build(get_settings())
    raise AttributeError(name)
