from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

import oplia_ctl.aiops.models
import oplia_ctl.dr.models
import oplia_ctl.finops.models
import oplia_ctl.identity.models  # noqa: F401
from oplia_ctl.db import Base, make_engine, make_session_factory
from oplia_ctl.safety import SafetyGate


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


PG_URL = os.environ.get("OPLIA_TEST_DATABASE_URL", "")


@pytest.fixture(scope="session")
def _pg_engine():
    """When OPLIA_TEST_DATABASE_URL is set, build the schema with the real Alembic migrations."""
    if not PG_URL:
        yield None
        return
    from alembic import command
    from alembic.config import Config

    os.environ["OPLIA_DATABASE_URL"] = PG_URL
    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    engine = make_engine(PG_URL)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(tmp_path, _pg_engine) -> Iterator[sessionmaker[Session]]:
    if _pg_engine is not None:
        with _pg_engine.begin() as conn:
            conn.execute(text("TRUNCATE action_proposals, audit_events, audit_head, control_flags, aiops_predictions, "
                              "finops_compliance_scans, finops_compliance_findings, finops_optimization_candidates, "
                              "jit_access_requests, dr_breaker_state, dr_incidents, "
                              "db_health_checks, db_consistency_runs, network_dial_changes, "
                              "dr_object_manifest, dr_replication_runs, dr_image_jobs, dr_jobs, "
                              "inventory_instances, inventory_scans, migration_hydration_docs "
                              "RESTART IDENTITY"))
        yield make_session_factory(_pg_engine)
        return
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    yield make_session_factory(engine)
    engine.dispose()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def gate(session_factory, clock) -> SafetyGate:
    return SafetyGate(session_factory, dry_run=False, require_approval=True, four_eyes=True,
                      proposal_ttl=timedelta(minutes=60), clock=clock)


class RecordingExecutor:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[dict] = []
        self.fail = fail

    def describe(self, payload: dict) -> str:
        return f"would act on {payload}"

    def __call__(self, payload: dict) -> dict:
        self.calls.append(payload)
        if self.fail:
            raise RuntimeError("boom")
        return {"ok": True}


@pytest.fixture
def executor() -> RecordingExecutor:
    return RecordingExecutor()
