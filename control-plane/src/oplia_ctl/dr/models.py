"""Circuit-breaker state per replication stream and incident records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class BreakerStateRow(Base):
    __tablename__ = "dr_breaker_state"

    stream: Mapped[str] = mapped_column(String(64), primary_key=True)
    state: Mapped[str] = mapped_column(String(8))            # CLOSED (forwarding) | OPEN (severed)
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    changed_by: Mapped[str] = mapped_column(String(256))
    # set by a reset, consumed by the relay: "release" (forward the held bundle) or "discard"
    pending_decision: Mapped[str | None] = mapped_column(String(16), nullable=True)


class DrIncidentRow(Base):
    __tablename__ = "dr_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    stream: Mapped[str] = mapped_column(String(64), index=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    trigger: Mapped[str] = mapped_column(String(32))          # rule name or "manual"
    summary: Mapped[str] = mapped_column(Text)
    findings_json: Mapped[str] = mapped_column(Text)
    positions_json: Mapped[str] = mapped_column(Text)         # source positions of the held bundle
    dump_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    dump_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actions_json: Mapped[str] = mapped_column(Text)           # sever / alerts / locks, with results
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
