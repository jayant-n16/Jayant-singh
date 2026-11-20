"""ASGI entrypoint: ``uvicorn oplia_ctl.main:app``."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from fastapi import FastAPI

import oplia_ctl.aiops.models
import oplia_ctl.databases.models
import oplia_ctl.dr.models
import oplia_ctl.finops.models
import oplia_ctl.identity.models
import oplia_ctl.inventory.models
import oplia_ctl.network.models
import oplia_ctl.replication.models  # noqa: F401
from oplia_ctl.aiops.config import AIOpsSettings, build_notifier, build_scheduler
from oplia_ctl.aiops.engine import AIOpsEngine
from oplia_ctl.aiops.escalation import EscalationScheduler
from oplia_ctl.aiops.executors import (
    ACTION_HPA_SCALE,
    ACTION_ROLLING_RESTART,
    ACTION_RUNBOOK,
    K8sHpaScaleExecutor,
    K8sRollingRestartExecutor,
    K8sRunbookJobExecutor,
    NotifyBeforeActExecutor,
)
from oplia_ctl.aiops.matrix import load_matrix
from oplia_ctl.aiops.runbooks import load_runbooks
from oplia_ctl.api import create_app, sqlalchemy_ping
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.cloud.aws_isolation import AwsInstanceIsolationExecutor
from oplia_ctl.cloud.azure_isolation import AzureNicIsolationExecutor
from oplia_ctl.cloud.k8s_isolation import K8sNamespaceIsolationExecutor
from oplia_ctl.cloud.power import ComputePowerExecutor
from oplia_ctl.config import Settings, get_settings
from oplia_ctl.databases.config import DatabaseSettings
from oplia_ctl.databases.consistency import ACTION_DR_RESYNC, ConsistencyChecker
from oplia_ctl.databases.registry import DatabaseRegistry
from oplia_ctl.databases.resync import ResyncExecutor
from oplia_ctl.db import Base, make_engine, make_session_factory
from oplia_ctl.dr.config import DRSettings, build_breaker
from oplia_ctl.drivers.cicd import build_cicd_driver
from oplia_ctl.finops.config import FinOpsSettings, build_executors
from oplia_ctl.finops.optimizer import WindowGuard
from oplia_ctl.http import ResilientClient
from oplia_ctl.identity.config import IdentitySettings, build_providers
from oplia_ctl.identity.jit import JitService, load_catalog
from oplia_ctl.identity.sweep import ACTION_DISABLE_INACTIVE, DisableInactiveExecutor
from oplia_ctl.integrations import build_integrations
from oplia_ctl.lifecycle.manager import ACTION_IAC_DESTROY
from oplia_ctl.network.service import NetworkService, NetworkSettings, TrafficDialExecutor
from oplia_ctl.remediation.drift import ACTION_DRIFT_REMEDIATE, PipelineDispatchExecutor
from oplia_ctl.replication.config import ACTION_PIPELINE, ReplicationSettings, build_job_machines, gate_audit
from oplia_ctl.replication.images import ACTION_IMAGE_REPLICATE, ImageReplicator
from oplia_ctl.replication.objects import ACTION_OBJECT_DELETE, ACTION_OBJECT_SYNC, ObjectReplicator
from oplia_ctl.replication.pipelines import KafkaConnect, PipelineExecutor
from oplia_ctl.replication.stores import build_store
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
        "compute.power": ComputePowerExecutor(secrets=secrets, client=client),
    }
    dr_cfg = DRSettings()
    dr_breaker = None
    if dr_cfg.stream:
        dr_breaker = build_breaker(dr_cfg, gate=gate, session_factory=make_session_factory(engine),
                                   secrets=secrets, client=client,
                                   notifier=build_notifier(AIOpsSettings(), secrets, client))
    identity_cfg = IdentitySettings()
    jit: JitService | None = None
    providers = build_providers(identity_cfg, secrets, client)
    if providers:
        executors[ACTION_DISABLE_INACTIVE] = DisableInactiveExecutor(
            providers, inactive_days=identity_cfg.inactive_days)
    if identity_cfg.catalog_path:
        jit = JitService(gate=gate, session_factory=make_session_factory(engine), providers=providers,
                         catalog=load_catalog(identity_cfg.catalog_path, providers))
    finops_cfg = FinOpsSettings()
    db_cfg = DatabaseSettings()
    executors.update(build_executors(finops_cfg, WindowGuard(finops_cfg.maintenance_windows)))
    aiops_cfg = AIOpsSettings()
    aiops_engine: AIOpsEngine | None = None
    escalation: EscalationScheduler | None = None
    if aiops_cfg.cluster_name:
        sf = make_session_factory(engine)
        notifier = build_notifier(aiops_cfg, secrets, client)
        runbooks = load_runbooks(aiops_cfg.runbooks_path)
        aiops_engine = AIOpsEngine(
            gate=gate, notifier=notifier, rules=load_matrix(aiops_cfg.matrix_path), runbooks=runbooks,
            cluster_name=aiops_cfg.cluster_name, cooldown=timedelta(minutes=aiops_cfg.cooldown_minutes),
            public_base_url=aiops_cfg.public_base_url)
        escalation = build_scheduler(aiops_cfg, sf, notifier)
        req = aiops_cfg.require_pre_action_notification
        executors[ACTION_ROLLING_RESTART] = NotifyBeforeActExecutor(
            K8sRollingRestartExecutor(), notifier, require_delivery=req)
        executors[ACTION_HPA_SCALE] = NotifyBeforeActExecutor(
            K8sHpaScaleExecutor(max_step=aiops_cfg.hpa_max_step, max_ceiling=aiops_cfg.hpa_max_ceiling,
                                cpu_target_step=aiops_cfg.hpa_cpu_target_step,
                                cpu_target_floor=aiops_cfg.hpa_cpu_target_floor),
            notifier, require_delivery=req)
        executors[ACTION_RUNBOOK] = NotifyBeforeActExecutor(
            K8sRunbookJobExecutor(runbooks), notifier, require_delivery=req)
    soar_cfg = SOARSettings()
    soar_exporter = None
    sink = None
    if soar_cfg.siem_endpoint:
        sink = SIEMSink(endpoint=soar_cfg.siem_endpoint, fmt=soar_cfg.siem_format,
                        token_secret=soar_cfg.siem_token_secret, secrets=secrets, client=client,
                        dead_letter_path=soar_cfg.dead_letter_path)
        soar_exporter = SOARExporter(gate=gate, sink=sink, threshold=soar_cfg.threshold)
    net_cfg = NetworkSettings()
    network = (NetworkService(net_cfg, make_session_factory(engine), secrets=secrets, client=client)
               if net_cfg.enabled() else None)
    if network is not None and net_cfg.endpoint_groups:
        executors["network.traffic_dial"] = TrafficDialExecutor(network)
    rep_cfg = ReplicationSettings()
    kafka_connect = (KafkaConnect(rep_cfg.kafka_connect_url, client, secrets, rep_cfg.kafka_connect_auth_secret)
                     if rep_cfg.kafka_connect_url else None)
    object_replicator = (ObjectReplicator(rep_cfg.object_pairs, make_session_factory(engine), build_store,
                                          rep_cfg.max_objects_per_run, rep_cfg.verify_readback)
                         if rep_cfg.object_pairs else None)
    image_replicator = ImageReplicator(rep_cfg.images, make_session_factory(engine)) if rep_cfg.images else None
    if kafka_connect is not None:
        executors[ACTION_PIPELINE] = PipelineExecutor(kafka_connect)
    if object_replicator is not None:
        executors[ACTION_OBJECT_SYNC] = object_replicator
        executors[ACTION_OBJECT_DELETE] = object_replicator.deletion_executor()
    if image_replicator is not None:
        executors[ACTION_IMAGE_REPLICATE] = image_replicator
    dr_jobs = build_job_machines(rep_cfg, make_session_factory(engine), audit=gate_audit(gate))
    for machine in dr_jobs.values():
        executors[machine.action] = machine
    integrations = build_integrations(
        settings=settings, secrets=secrets, client=client, finops_cfg=finops_cfg, providers=providers,
        identity_cfg=identity_cfg, aiops_cfg=aiops_cfg, soar_cfg=soar_cfg, siem_sink=sink,
        alerting_in_use=bool(aiops_cfg.cluster_name or dr_cfg.stream))
    verifier = OIDCVerifier(issuer=settings.oidc_issuer, audience=settings.oidc_audience,
                            jwks_url=settings.oidc_jwks_url, roles_claim=settings.oidc_roles_claim)
    logging.getLogger("oplia").info("control plane starting: env=%s dry_run=%s require_approval=%s",
                                    settings.environment, settings.dry_run, settings.require_approval)
    db_registry = (DatabaseRegistry(db_cfg.databases, secrets, make_session_factory(engine))
                   if db_cfg.databases else None)
    consistency = None
    if db_registry is not None and any(d.dr_of for d in db_cfg.databases):
        breaker_state = None
        if dr_breaker is not None:
            b = dr_breaker

            def breaker_state() -> dict[str, Any] | None:
                state, incident, decision = b.store.state(b.stream)
                return {"stream": b.stream, "state": state, "incident_id": incident, "pending_decision": decision}
        consistency = ConsistencyChecker(db_registry, gate, make_session_factory(engine),
                                         breaker_state=breaker_state)
        executors[ACTION_DR_RESYNC] = ResyncExecutor(db_registry, kafka_connect=kafka_connect)
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
        aiops_engine=aiops_engine,
        escalation=escalation,
        alertmanager_token_secret=aiops_cfg.alertmanager_token_secret,
        finops_sf=make_session_factory(engine),
        jit=jit,
        dr_breaker=dr_breaker,
        db_ping=sqlalchemy_ping(engine),
        db_registry=db_registry,
        consistency=consistency,
        integrations=integrations,
        network=network,
        kafka_connect=kafka_connect,
        object_replicator=object_replicator,
        image_replicator=image_replicator,
        dr_jobs=dr_jobs,
        inventory_sf=make_session_factory(engine) if (
            finops_cfg.aws_regions or finops_cfg.azure_subscriptions or finops_cfg.gcp_scopes
            or finops_cfg.ibm_account_id) else None,
    )


def __getattr__(name: str) -> FastAPI:
    # Lazy so importing this module (e.g. in tests or tooling) does not read env or open the DB.
    if name == "app":
        return build(get_settings())
    raise AttributeError(name)
