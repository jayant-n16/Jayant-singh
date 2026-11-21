"""Settings and wiring for the migration engine (env prefix ``OPLIA_MIGRATION_``)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.migration.ai import AIProviderConfig
from oplia_ctl.migration.cdc import CdcSettings
from oplia_ctl.replication.jobs import JobMachine


class MigrationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_MIGRATION_", extra="ignore")

    online_ddl: bool = False                                     # FR-02 jobs on OPLIA_DATABASES (postgres/mysql)
    synthesis: bool = False                                      # FR-01 schema synthesis jobs
    max_batches_per_step: int = Field(default=200, ge=1, le=100000)
    ai_providers: list[AIProviderConfig] = Field(default_factory=list)   # JSON list
    # Stored-routine bodies are customer code: sending them to an AI vendor is off unless explicitly allowed.
    ai_allow_source_code: bool = False
    cdc: CdcSettings | None = None                               # FR-03 pipelines (JSON object)
    lag_probe: bool = False                                      # FR-03 lag measurement on OPLIA_DATABASES

    def enabled(self) -> bool:
        return self.online_ddl or self.synthesis or self.cdc is not None or self.lag_probe


def build_migration_machines(session_factory: Any, secrets: Any = None,
                             audit: Callable[[str, dict[str, Any]], None] | None = None,
                             cfg: MigrationSettings | None = None, http: Any = None) -> list[JobMachine]:
    cfg = cfg or MigrationSettings()
    out: list[JobMachine] = []
    if not cfg.enabled():
        return out
    from oplia_ctl.databases.config import DatabaseSettings
    from oplia_ctl.databases.registry import DatabaseRegistry

    dbs = DatabaseSettings().databases
    reg = None
    if dbs:
        if secrets is None:
            raise ValueError("the migration engine needs the secret provider (database DSNs are secrets)")
        reg = DatabaseRegistry(dbs, secrets, session_factory)
    if cfg.online_ddl:
        from oplia_ctl.migration.online_ddl import SUPPORTED_ENGINES, OnlineSchemaChange, SchemaContract

        if reg is None or not any(d.engine in SUPPORTED_ENGINES for d in dbs):
            raise ValueError("OPLIA_MIGRATION_ONLINE_DDL needs a postgres or mysql entry in OPLIA_DATABASES")
        expand = OnlineSchemaChange(reg, session_factory, audit=audit, max_batches_per_step=cfg.max_batches_per_step)
        out += [expand, SchemaContract(expand, reg, session_factory, audit=audit,
                                       max_batches_per_step=cfg.max_batches_per_step)]
    if cfg.synthesis:
        from oplia_ctl.migration.ai import build_providers
        from oplia_ctl.migration.synthesis import SchemaSynthesis

        providers: dict[str, Any] = {}
        if cfg.ai_providers:
            if http is None:
                from oplia_ctl.http import ResilientClient

                http = ResilientClient(timeout=120.0, max_retries=2)
            providers = dict(build_providers(cfg.ai_providers, http, secrets))
        out.append(SchemaSynthesis(reg, session_factory, providers=providers,
                                   allow_source_code_to_ai=cfg.ai_allow_source_code, audit=audit))
    if cfg.cdc is not None:
        from oplia_ctl.migration.cdc import CdcPipeline

        kc = None
        if cfg.cdc.kafka_connect:
            from oplia_ctl.http import ResilientClient
            from oplia_ctl.replication.config import ReplicationSettings
            from oplia_ctl.replication.pipelines import KafkaConnect

            rep = ReplicationSettings()
            if not rep.kafka_connect_url:
                raise ValueError("cdc.kafka_connect needs OPLIA_REPLICATION_KAFKA_CONNECT_URL")
            kc = KafkaConnect(rep.kafka_connect_url, ResilientClient(timeout=30.0, max_retries=2), secrets,
                              rep.kafka_connect_auth_secret)
        out.append(CdcPipeline(cfg.cdc, session_factory, registry=reg, kafka_connect=kc, secrets=secrets, audit=audit))
    if cfg.lag_probe:
        from oplia_ctl.migration.cdc import CdcLagProbe

        if reg is None:
            raise ValueError("OPLIA_MIGRATION_LAG_PROBE needs OPLIA_DATABASES")
        out.append(CdcLagProbe(reg, session_factory, audit=audit))
    return out
