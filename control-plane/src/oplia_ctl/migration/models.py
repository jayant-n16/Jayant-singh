"""Migration engine state: documents being hydrated from CDC events (FR-04)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class HydrationDocRow(Base):
    """One target document (root row + embedded children). ``has_root`` is false while only children have
    arrived (CDC does not guarantee parent-before-child across tables); such documents are not written."""

    __tablename__ = "migration_hydration_docs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)        # sha256(pipeline/collection/key)
    pipeline: Mapped[str] = mapped_column(String(63), index=True)
    collection: Mapped[str] = mapped_column(String(128))
    doc_key: Mapped[str] = mapped_column(String(512))
    doc_json: Mapped[str] = mapped_column(Text)
    has_root: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
