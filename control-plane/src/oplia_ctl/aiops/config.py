"""``OPLIA_AIOPS_*`` settings and construction of the AIOps components."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.aiops.escalation import DEFAULT_POLICY, EscalationPolicy, EscalationScheduler
from oplia_ctl.aiops.notify import (
    PAGERDUTY_EVENTS_URL,
    Channel,
    IncidentNotifier,
    PagerDutyChannel,
    SlackChannel,
)
from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

log = logging.getLogger("oplia.aiops")


class AIOpsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_AIOPS_", extra="ignore")

    # Empty cluster name = AIOps disabled (endpoints answer 503).
    cluster_name: str = ""
    channels: list[Literal["pagerduty", "slack"]] = ["pagerduty", "slack"]
    pagerduty_routing_key_secret: str = "pagerduty_routing_key"
    pagerduty_events_url: str = PAGERDUTY_EVENTS_URL
    slack_webhook_secret: str = "slack_webhook_url"
    alertmanager_token_secret: str = "alertmanager_webhook_token"
    require_pre_action_notification: bool = True
    matrix_path: str = ""
    runbooks_path: str = ""
    cooldown_minutes: Annotated[int, Field(ge=1, le=24 * 60)] = 30
    hpa_max_step: Annotated[int, Field(ge=1, le=20)] = 2
    hpa_max_ceiling: Annotated[int, Field(ge=1, le=1000)] = 50
    hpa_cpu_target_step: Annotated[int, Field(ge=1, le=50)] = 10
    hpa_cpu_target_floor: Annotated[int, Field(ge=10, le=95)] = 40
    public_base_url: str = ""
    prediction_horizon_minutes: Annotated[int, Field(ge=15, le=24 * 60)] = 240
    escalation_policy: EscalationPolicy = DEFAULT_POLICY
    escalation_max_attempts: Annotated[int, Field(ge=1, le=20)] = 5
    escalator_interval_seconds: Annotated[float, Field(ge=5, le=3600)] = 60.0

    @field_validator("channels")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(v) != len(set(v)):
            raise ValueError("channels must not repeat")
        return v


def build_notifier(cfg: AIOpsSettings, secrets: SecretProvider, client: ResilientClient) -> IncidentNotifier:
    channels: list[Channel] = []
    if "pagerduty" in cfg.channels:
        channels.append(PagerDutyChannel(secrets=secrets, client=client,
                                         routing_key_secret=cfg.pagerduty_routing_key_secret,
                                         events_url=cfg.pagerduty_events_url))
    if "slack" in cfg.channels:
        channels.append(SlackChannel(secrets=secrets, client=client, webhook_secret=cfg.slack_webhook_secret))
    return IncidentNotifier(channels)


def build_scheduler(cfg: AIOpsSettings, sf: sessionmaker[Session], notifier: IncidentNotifier) -> EscalationScheduler:
    return EscalationScheduler(session_factory=sf, notifier=notifier, policy=cfg.escalation_policy,
                               horizon=timedelta(minutes=cfg.prediction_horizon_minutes),
                               max_attempts=cfg.escalation_max_attempts)


def escalator_main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    import argparse

    import oplia_ctl.aiops.models  # noqa: F401  (register table)
    from oplia_ctl.aiops.escalation import run_forever
    from oplia_ctl.config import get_settings
    from oplia_ctl.db import Base, make_engine, make_session_factory
    from oplia_ctl.secrets import build_secret_provider

    parser = argparse.ArgumentParser(description="Route predictive risks to PagerDuty/Slack on schedule.")
    parser.add_argument("--once", action="store_true", help="run one pass and exit (CronJob mode)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    cfg = AIOpsSettings()
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    client = ResilientClient(timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries)
    scheduler = build_scheduler(cfg, make_session_factory(engine),
                                build_notifier(cfg, build_secret_provider(settings.secret_provider), client))
    if args.once:
        print(json.dumps(scheduler.run_due()))
        return
    run_forever(scheduler, cfg.escalator_interval_seconds)
