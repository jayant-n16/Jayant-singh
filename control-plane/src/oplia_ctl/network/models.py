"""History of executed traffic-dial changes (used for the minimum hold time between increases)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class TrafficDialChangeRow(Base):
    __tablename__ = "network_dial_changes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    group_key: Mapped[str] = mapped_column(String(63), index=True)
    endpoint_group_arn: Mapped[str] = mapped_column(String(512))
    from_percent: Mapped[float] = mapped_column(Float)
    to_percent: Mapped[float] = mapped_column(Float)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)   # also in the proposal payload
