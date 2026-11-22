"""Cached compute inventory (written only by the scan job; the API never calls the clouds)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class InventoryInstanceRow(Base):
    __tablename__ = "inventory_instances"
    __table_args__ = (UniqueConstraint("cloud", "resource_id", name="uq_inventory_instance"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    cloud: Mapped[str] = mapped_column(String(8), index=True)
    scope: Mapped[str] = mapped_column(String(256), index=True)
    region: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(128))
    resource_id: Mapped[str] = mapped_column(String(1024))
    name: Mapped[str] = mapped_column(String(512))
    size: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    tags_json: Mapped[str] = mapped_column(Text, default="{}")
    tag_compliant: Mapped[bool] = mapped_column(Boolean)
    tag_issues_json: Mapped[str] = mapped_column(Text, default="[]")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    gone_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InventoryScanRow(Base):
    __tablename__ = "inventory_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    instances_seen: Mapped[int] = mapped_column(Integer, default=0)
    new_instances: Mapped[int] = mapped_column(Integer, default=0)
    gone_instances: Mapped[int] = mapped_column(Integer, default=0)
    source_errors_json: Mapped[str] = mapped_column(Text, default="[]")
