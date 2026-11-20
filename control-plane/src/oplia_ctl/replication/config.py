"""Settings and process entry points for DR replication."""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.replication.images import ImageSettings
from oplia_ctl.replication.objects import ObjectPair

ACTION_PIPELINE = "dr.pipeline"


class ReplicationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_REPLICATION_", extra="ignore")

    object_pairs: list[ObjectPair] = Field(default_factory=list)       # JSON list
    images: ImageSettings | None = None                                 # JSON object
    kafka_connect_url: str = ""
    kafka_connect_auth_secret: str = ""                                 # secret name holding "user:password"
    max_objects_per_run: int = Field(default=5000, ge=1, le=100000)
    verify_readback: bool = True

    def enabled(self) -> bool:
        return bool(self.object_pairs or self.images or self.kafka_connect_url)


def _setup() -> tuple[Any, Any]:  # pragma: no cover - process wiring
    from oplia_ctl.config import get_settings
    from oplia_ctl.db import Base, make_engine, make_session_factory
    from oplia_ctl.safety import SafetyGate

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    from datetime import timedelta
    gate = SafetyGate(make_session_factory(engine), dry_run=settings.dry_run,
                      require_approval=settings.require_approval, four_eyes=settings.four_eyes,
                      proposal_ttl=timedelta(minutes=settings.proposal_ttl_minutes))
    return gate, make_session_factory(engine)


def object_plan_main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    """CronJob: plan every object pair and create a dr.object_sync proposal where there is work."""
    import hashlib

    from oplia_ctl.replication.objects import ACTION_OBJECT_SYNC, ObjectReplicator
    from oplia_ctl.replication.stores import build_store

    cfg = ReplicationSettings()
    if not cfg.object_pairs:
        raise SystemExit("OPLIA_REPLICATION_OBJECT_PAIRS is empty")
    gate, sf = _setup()
    rep = ObjectReplicator(cfg.object_pairs, sf, build_store, cfg.max_objects_per_run, cfg.verify_readback)
    for name in rep.pairs:
        plan = rep.plan(name)
        if not plan["objects"]:
            print(json.dumps({"pair": name, "objects": 0}))
            continue
        digest = hashlib.sha256(json.dumps(plan["objects"], sort_keys=True).encode()).hexdigest()[:32]
        p = gate.propose(action_type=ACTION_OBJECT_SYNC, target=name,
                         payload={"pair": name, "objects": plan["objects"]},
                         reason=f"scheduled DR object sync {name}: {len(plan['objects'])} object(s), "
                                f"{plan['bytes']} bytes", requested_by="scheduler",
                         idempotency_key=f"objsync-{name}-{digest}")
        print(json.dumps({"pair": name, "objects": len(plan["objects"]), "proposal": p.id}))


def image_worker_main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    """CronJob: advance queued/running image replication jobs."""
    from oplia_ctl.replication.images import ImageReplicator

    cfg = ReplicationSettings()
    if cfg.images is None:
        raise SystemExit("OPLIA_REPLICATION_IMAGES is not set")
    _, sf = _setup()
    print(json.dumps(ImageReplicator(cfg.images, sf).run_pending(), indent=2))
