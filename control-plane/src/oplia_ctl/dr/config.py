"""``OPLIA_DR_*`` settings and the ``oplia-dr-breaker`` entry point (one process per stream)."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.dr.breaker import CircuitBreaker, WebhookSpec
from oplia_ctl.dr.decode import Engine, Format
from oplia_ctl.dr.lockers import TargetSpec, build_locker
from oplia_ctl.dr.rules import RateMonitor

log = logging.getLogger("oplia.dr")


class DRSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_DR_", extra="ignore")

    stream: str = ""                                   # empty = DR breaker not configured
    source_format: Format = "debezium"
    source_engine: Engine = "postgres"
    sql_dialect: str = "postgres"
    source_topics: list[str] = Field(default_factory=list)
    sink_topic: str = ""
    kafka_source: dict[str, str] = Field(default_factory=dict)   # non-secret librdkafka settings
    kafka_sink: dict[str, str] = Field(default_factory=dict)
    kafka_sasl_password_secret: str = ""               # secret name; added as sasl.password
    targets: list[TargetSpec] = Field(default_factory=list)
    webhooks: list[WebhookSpec] = Field(default_factory=list)
    spike_percent: Annotated[float, Field(gt=0, le=100000)] = 500.0
    window_seconds: Annotated[int, Field(ge=10, le=3600)] = 60
    baseline_windows: Annotated[int, Field(ge=1, le=60)] = 5
    min_mutations: Annotated[int, Field(ge=1)] = 1000
    block_undecodable: bool = True
    quarantine_dir: str = "/var/lib/oplia/dr-quarantine"
    lock_timeout_seconds: Annotated[float, Field(ge=5, le=600)] = 60.0
    max_bundle_records: Annotated[int, Field(ge=1, le=10000)] = 500
    transit_mount: str = "transit-dr-broker"
    transit_key: str = ""                              # set (e.g. circuit-breaker-key) to protect dumps
    sign_bundles: bool = False                         # HMAC header on every forwarded record (needs transit_key)

    def rate_monitor(self) -> RateMonitor:
        return RateMonitor(spike_percent=self.spike_percent, window_seconds=self.window_seconds,
                           baseline_windows=self.baseline_windows, min_mutations=self.min_mutations)


def build_breaker(cfg: DRSettings, *, gate: Any, session_factory: Any, secrets: Any, client: Any,
                  notifier: Any) -> CircuitBreaker:
    names = [t.name for t in cfg.targets]
    if len(names) != len(set(names)):
        raise ValueError("DR target names must be unique")
    return CircuitBreaker(protector=build_protector(cfg, secrets),
        stream=cfg.stream, gate=gate, session_factory=session_factory, secrets=secrets, client=client,
        lockers=[build_locker(t, secrets) for t in cfg.targets], webhooks=cfg.webhooks, notifier=notifier,
        quarantine_dir=cfg.quarantine_dir, rate=cfg.rate_monitor(), block_undecodable=cfg.block_undecodable,
        lock_timeout_seconds=cfg.lock_timeout_seconds)


def build_protector(cfg: DRSettings, secrets: Any) -> Any:
    if not cfg.transit_key:
        if cfg.sign_bundles:
            raise ValueError("OPLIA_DR_SIGN_BUNDLES needs OPLIA_DR_TRANSIT_KEY")
        return None
    client = getattr(secrets, "client", None)
    if client is None:
        raise ValueError("OPLIA_DR_TRANSIT_KEY needs OPLIA_SECRET_PROVIDER=vault")
    from oplia_ctl.dr.crypto import TransitProtector

    return TransitProtector(client, cfg.transit_mount, cfg.transit_key)


def main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    import argparse
    from datetime import timedelta

    import oplia_ctl.dr.models  # noqa: F401
    from oplia_ctl.aiops.config import AIOpsSettings, build_notifier
    from oplia_ctl.config import get_settings
    from oplia_ctl.db import Base, make_engine, make_session_factory
    from oplia_ctl.dr.relay import KafkaSink, KafkaSource, Relay
    from oplia_ctl.http import ResilientClient
    from oplia_ctl.safety import SafetyGate
    from oplia_ctl.secrets import build_secret_provider

    argparse.ArgumentParser(
        description="DR replication circuit breaker: CDC topic -> inspect -> DR topic.").parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    cfg = DRSettings()
    if not (cfg.stream and cfg.source_topics and cfg.sink_topic):
        raise SystemExit("set OPLIA_DR_STREAM, OPLIA_DR_SOURCE_TOPICS and OPLIA_DR_SINK_TOPIC")
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    sf = make_session_factory(engine)
    secrets = build_secret_provider(settings.secret_provider)
    client = ResilientClient(timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries)
    gate = SafetyGate(sf, dry_run=settings.dry_run, require_approval=settings.require_approval,
                      four_eyes=settings.four_eyes, proposal_ttl=timedelta(minutes=settings.proposal_ttl_minutes))
    breaker = build_breaker(cfg, gate=gate, session_factory=sf, secrets=secrets, client=client,
                            notifier=build_notifier(AIOpsSettings(), secrets, client))
    extra = {"sasl.password": secrets.get(cfg.kafka_sasl_password_secret)} if cfg.kafka_sasl_password_secret else {}
    source = KafkaSource(config={**cfg.kafka_source, **extra}, topics=cfg.source_topics, fmt=cfg.source_format,
                         engine=cfg.source_engine, sql_dialect=cfg.sql_dialect, max_records=cfg.max_bundle_records)
    protector = build_protector(cfg, secrets)
    signer = protector.sign if (cfg.sign_bundles and protector is not None) else None
    relay = Relay(breaker=breaker, source=source,
                  sink_factory=lambda: KafkaSink(config={**cfg.kafka_sink, **extra}, topic=cfg.sink_topic,
                                                 signer=signer),
                  session_factory=sf, rate_factory=cfg.rate_monitor)
    relay.run_forever()
