"""Stored results of database health and DR consistency checks (definitions live in configuration)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class DbHealthCheckRow(Base):
    __tablename__ = "db_health_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    database: Mapped[str] = mapped_column(String(63), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ok: Mapped[bool] = mapped_column(Boolean)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    detail_json: Mapped[str] = mapped_column(Text, default="{}")   # version, role, read_only, replication
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(256))


class ConsistencyRunRow(Base):
    __tablename__ = "db_consistency_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    pair: Mapped[str] = mapped_column(String(63), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), index=True)   # CONSISTENT / DRIFT / FAILED
    summary: Mapped[str] = mapped_column(Text, default="")
    report_json: Mapped[str] = mapped_column(Text, default="{}")
    triggered_by: Mapped[str] = mapped_column(String(256))
    proposal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
