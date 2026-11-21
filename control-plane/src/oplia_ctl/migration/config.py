"""Settings and wiring for the migration engine (env prefix ``OPLIA_MIGRATION_``)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.replication.jobs import JobMachine


class MigrationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_MIGRATION_", extra="ignore")

    online_ddl: bool = False                                     # FR-02 jobs on OPLIA_DATABASES (postgres/mysql)
    max_batches_per_step: int = Field(default=200, ge=1, le=100000)


def build_migration_machines(session_factory: Any, secrets: Any = None,
                             audit: Callable[[str, dict[str, Any]], None] | None = None,
                             cfg: MigrationSettings | None = None) -> list[JobMachine]:
    cfg = cfg or MigrationSettings()
    out: list[JobMachine] = []
    if cfg.online_ddl:
        from oplia_ctl.databases.config import DatabaseSettings
        from oplia_ctl.databases.registry import DatabaseRegistry
        from oplia_ctl.migration.online_ddl import SUPPORTED_ENGINES, OnlineSchemaChange, SchemaContract

        dbs = DatabaseSettings().databases
        if not any(d.engine in SUPPORTED_ENGINES for d in dbs):
            raise ValueError("OPLIA_MIGRATION_ONLINE_DDL needs a postgres or mysql entry in OPLIA_DATABASES")
        if secrets is None:
            raise ValueError("online DDL needs the secret provider (database DSNs are secrets)")
        reg = DatabaseRegistry(dbs, secrets, session_factory)
        expand = OnlineSchemaChange(reg, session_factory, audit=audit, max_batches_per_step=cfg.max_batches_per_step)
        out += [expand, SchemaContract(expand, reg, session_factory, audit=audit,
                                       max_batches_per_step=cfg.max_batches_per_step)]
    return out
