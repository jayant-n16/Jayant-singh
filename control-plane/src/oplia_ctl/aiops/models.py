"""Persistence for predictive escalations."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class PredictionStatus(enum.StrEnum):
    SCHEDULED = "SCHEDULED"      # waiting for its notify_at time
    ESCALATING = "ESCALATING"    # claimed by one scheduler run
    ESCALATED = "ESCALATED"      # delivered to every requested channel
    EXPIRED = "EXPIRED"          # predicted time passed before it could be escalated
    CANCELLED = "CANCELLED"      # withdrawn by an operator
    FAILED = "FAILED"            # delivery kept failing; needs a human


class PredictionRow(Base):
    __tablename__ = "aiops_predictions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    risk_id: Mapped[str] = mapped_column(String(128), unique=True)
    service: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    probability: Mapped[float] = mapped_column(Float)
    predicted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    notify_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    summary: Mapped[str] = mapped_column(Text)
    detail_json: Mapped[str] = mapped_column(Text)
    channels_json: Mapped[str] = mapped_column(Text)  # {"requested": [...], "delivered": [...]}
    status: Mapped[str] = mapped_column(String(16), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
