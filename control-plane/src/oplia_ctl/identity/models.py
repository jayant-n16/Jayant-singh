"""JIT access requests (the document's schema plus the fields needed to run it safely)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class JitRequestRow(Base):
    __tablename__ = "jit_access_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # --- fields named in the document
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    requested_role: Mapped[str] = mapped_column(String(64))
    target_cloud_account: Mapped[str] = mapped_column(String(128))
    expiration_minutes: Mapped[int] = mapped_column(Integer)
    approval_status: Mapped[str] = mapped_column(String(16), index=True)  # PENDING|APPROVED|REJECTED|EXPIRED
    # --- operational fields
    idp: Mapped[str] = mapped_column(String(8))
    group_ref: Mapped[str] = mapped_column(String(512))
    justification: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(256))
    # NONE | ACTIVE | REVOKED | DRY_RUN | GRANT_FAILED
    access_status: Mapped[str] = mapped_column(String(16), index=True)
    proposal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    granted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    revoke_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    alerted: Mapped[int] = mapped_column(Integer, default=0)
