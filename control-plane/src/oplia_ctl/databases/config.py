"""Settings and process entry points for the database registry."""

from __future__ import annotations

import json
import logging

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.databases.registry import DatabaseSpec


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_", extra="ignore")

    databases: list[DatabaseSpec] = Field(default_factory=list)   # OPLIA_DATABASES (JSON list)


def health_main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    """CronJob: check every configured database and store the results."""
    from oplia_ctl.config import get_settings
    from oplia_ctl.databases.registry import DatabaseRegistry
    from oplia_ctl.db import Base, make_engine, make_session_factory
    from oplia_ctl.secrets import build_secret_provider

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    cfg = DatabaseSettings()
    if not cfg.databases:
        raise SystemExit("OPLIA_DATABASES is empty")
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    reg = DatabaseRegistry(cfg.databases, build_secret_provider(settings.secret_provider),
                           make_session_factory(engine))
    results = reg.check_all(triggered_by="scheduler")
    print(json.dumps([{k: r[k] for k in ("database", "ok", "latency_ms", "error")} for r in results], indent=2))
    if not all(r["ok"] for r in results):
        raise SystemExit(2)
