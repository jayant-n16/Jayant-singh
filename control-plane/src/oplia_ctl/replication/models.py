"""Replication state: object manifest, runs and VM image jobs."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class ObjectManifestRow(Base):
    __tablename__ = "dr_object_manifest"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    pair: Mapped[str] = mapped_column(String(63), index=True)
    key: Mapped[str] = mapped_column(String(1024))
    source_etag: Mapped[str] = mapped_column(String(256))
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    replicated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ReplicationRunRow(Base):
    __tablename__ = "dr_replication_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    pair: Mapped[str] = mapped_column(String(63), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16))          # OK / PARTIAL / FAILED
    copied: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")


class ImageJobRow(Base):
    __tablename__ = "dr_image_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_cloud: Mapped[str] = mapped_column(String(8))
    source_id: Mapped[str] = mapped_column(String(512))
    target_cloud: Mapped[str] = mapped_column(String(8))
    name: Mapped[str] = mapped_column(String(63))
    status: Mapped[str] = mapped_column(String(16), index=True)   # QUEUED/RUNNING/SUCCEEDED/FAILED
    step: Mapped[str] = mapped_column(String(32))
    state_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    requested_by: Mapped[str] = mapped_column(String(256))
