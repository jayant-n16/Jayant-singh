"""``OPLIA_FINOPS_*`` settings, component builders and the two CronJob entry points.

* ``oplia-finops-scan [--audit]`` - tag compliance scan. ``--audit`` is read-only: it prints the
  non-compliant resources and writes nothing (the document's "dry run audit mode").
* ``oplia-finops-optimize observe|window`` - record idle resources and propose clean-ups, or
  execute approved clean-ups inside the maintenance window.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Annotated, Any, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.finops.compliance import TagPolicy
from oplia_ctl.finops.inventory import (
    DEFAULT_IBM_QUERIES,
    AwsInventory,
    AzureInventory,
    Category,
    GcpInventory,
    IbmInventory,
    InventorySource,
)
from oplia_ctl.finops.optimizer import (
    ACTION_AZURE_DISK_DELETE,
    ACTION_EBS_DELETE,
    ACTION_EIP_RELEASE,
    ACTION_GCP_DISK_DELETE,
    PROTECTED_ENVIRONMENTS,
    AwsEbsDeleteExecutor,
    AwsEipReleaseExecutor,
    AwsIdleDetector,
    AzureDiskDeleteExecutor,
    AzureIdleDetector,
    GcpDiskDeleteExecutor,
    GcpIdleDetector,
    IdleDetector,
    MaintenanceWindow,
    WindowGuard,
)
from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

log = logging.getLogger("oplia.finops")


class FinOpsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_FINOPS_", extra="ignore")

    aws_regions: list[str] = Field(default_factory=list)
    azure_subscriptions: list[str] = Field(default_factory=list)
    gcp_scopes: list[str] = Field(default_factory=list)     # inventory: projects/x, folders/n, organizations/n
    gcp_projects: list[str] = Field(default_factory=list)   # idle-disk detection (project ids)
    ibm_account_id: str = ""
    ibm_api_key_secret: str = "ibm_cloud_api_key"
    ibm_queries: list[tuple[Category, str]] = Field(default_factory=lambda: list(DEFAULT_IBM_QUERIES))
    policy: TagPolicy = Field(default_factory=TagPolicy)
    alert_channels: list[Literal["pagerduty", "slack"]] = ["slack"]
    maintenance_windows: list[MaintenanceWindow] = Field(default_factory=list)
    idle_grace_days: Annotated[int, Field(ge=1, le=365)] = 7
    proposal_ttl_hours: Annotated[int, Field(ge=1, le=720)] = 192  # 8 days: survives until a weekly window
    protected_environments: list[str] = Field(default_factory=lambda: sorted(PROTECTED_ENVIRONMENTS))
    snapshot_wait_seconds: Annotated[int, Field(ge=60, le=6 * 3600)] = 1800

    @property
    def protected(self) -> frozenset[str]:
        return frozenset(e.lower() for e in self.protected_environments)


def build_sources(cfg: FinOpsSettings, secrets: SecretProvider, client: ResilientClient) -> list[InventorySource]:
    sources: list[InventorySource] = []
    if cfg.aws_regions:
        sources.append(AwsInventory(cfg.aws_regions))
    if cfg.azure_subscriptions:
        sources.append(AzureInventory(cfg.azure_subscriptions))
    if cfg.gcp_scopes:
        sources.append(GcpInventory(cfg.gcp_scopes))
    if cfg.ibm_account_id:
        sources.append(IbmInventory(account_id=cfg.ibm_account_id, secrets=secrets, client=client,
                                    api_key_secret=cfg.ibm_api_key_secret, queries=cfg.ibm_queries))
    return sources


def build_detectors(cfg: FinOpsSettings) -> list[IdleDetector]:
    dets: list[IdleDetector] = []
    if cfg.aws_regions:
        dets.append(AwsIdleDetector(cfg.aws_regions))
    if cfg.azure_subscriptions:
        dets.append(AzureIdleDetector(cfg.azure_subscriptions))
    if cfg.gcp_projects:
        dets.append(GcpIdleDetector(cfg.gcp_projects))
    return dets


def build_executors(cfg: FinOpsSettings, guard: WindowGuard) -> dict[str, Any]:
    kw: dict[str, Any] = {"protected_environments": cfg.protected}
    return {
        ACTION_EBS_DELETE: AwsEbsDeleteExecutor(guard, snapshot_wait_seconds=cfg.snapshot_wait_seconds, **kw),
        ACTION_EIP_RELEASE: AwsEipReleaseExecutor(guard, **kw),
        ACTION_AZURE_DISK_DELETE: AzureDiskDeleteExecutor(guard, lro_timeout_seconds=cfg.snapshot_wait_seconds, **kw),
        ACTION_GCP_DISK_DELETE: GcpDiskDeleteExecutor(guard, op_timeout_seconds=cfg.snapshot_wait_seconds, **kw),
    }


def _runtime() -> tuple[Any, Any, Any, FinOpsSettings]:  # pragma: no cover - process wiring
    import oplia_ctl.finops.models  # noqa: F401
    from oplia_ctl.config import get_settings
    from oplia_ctl.db import Base, make_engine, make_session_factory
    from oplia_ctl.secrets import build_secret_provider

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    return settings, make_session_factory(engine), build_secret_provider(settings.secret_provider), FinOpsSettings()


def scan_main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    import argparse

    from oplia_ctl.aiops.config import AIOpsSettings, build_notifier
    from oplia_ctl.finops.compliance import ComplianceScanner

    p = argparse.ArgumentParser(description="Multi-cloud tag compliance scan (Owner, CostCenter, Environment).")
    p.add_argument("--audit", action="store_true", help="read-only: print findings, write nothing, alert nobody")
    args = p.parse_args()
    settings, sf, secrets, cfg = _runtime()
    client = ResilientClient(timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries)
    sources = build_sources(cfg, secrets, client)
    if not sources:
        raise SystemExit("configure at least one of OPLIA_FINOPS_AWS_REGIONS / _AZURE_SUBSCRIPTIONS / "
                         "_GCP_SCOPES / _IBM_ACCOUNT_ID")
    if args.audit:
        report, bad = ComplianceScanner(session_factory=None, sources=sources, policy=cfg.policy).audit()
        print(json.dumps({**report.as_dict(), "noncompliant_resources": [
            {"cloud": e.resource.cloud, "id": e.resource.resource_id, "missing": e.missing,
             "wrong_case": e.wrong_case, "invalid": e.invalid} for e in bad]}, indent=2))
    else:
        notifier = build_notifier(AIOpsSettings(), secrets, client)
        report = ComplianceScanner(session_factory=sf, sources=sources, policy=cfg.policy, notifier=notifier,
                                   alert_channels=list(cfg.alert_channels)).run()
        print(json.dumps(report.as_dict(), indent=2))
    if report.source_errors:
        raise SystemExit(2)


def optimize_main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    import argparse

    from oplia_ctl.finops.optimizer import CostOptimizer
    from oplia_ctl.safety import SafetyGate

    p = argparse.ArgumentParser(description="Idle-resource clean-up through the safety gate.")
    p.add_argument("mode", choices=["observe", "window"])
    args = p.parse_args()
    settings, sf, _secrets, cfg = _runtime()
    gate = SafetyGate(sf, dry_run=settings.dry_run, require_approval=settings.require_approval,
                      four_eyes=settings.four_eyes, proposal_ttl=timedelta(minutes=settings.proposal_ttl_minutes))
    opt = CostOptimizer(gate=gate, session_factory=sf, detectors=build_detectors(cfg),
                        grace=timedelta(days=cfg.idle_grace_days),
                        proposal_ttl=timedelta(hours=cfg.proposal_ttl_hours), protected_environments=cfg.protected)
    if args.mode == "observe":
        report = opt.observe()
        print(json.dumps(report.as_dict(), indent=2, default=str))
        if report.detector_errors:
            raise SystemExit(2)
    else:
        guard = WindowGuard(cfg.maintenance_windows)
        print(json.dumps(opt.run_window(build_executors(cfg, guard), guard), indent=2))
