"""Shared compliance log and cost-optimisation candidates."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from oplia_ctl.db import Base


class ComplianceScanRow(Base):
    __tablename__ = "finops_compliance_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resources_scanned: Mapped[int] = mapped_column(Integer, default=0)
    noncompliant: Mapped[int] = mapped_column(Integer, default=0)
    new_findings: Mapped[int] = mapped_column(Integer, default=0)
    resolved_findings: Mapped[int] = mapped_column(Integer, default=0)
    source_errors_json: Mapped[str] = mapped_column(Text, default="[]")
    alert_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class ComplianceFindingRow(Base):
    """One row per non-compliant resource; kept and resolved, never deleted (audit trail)."""

    __tablename__ = "finops_compliance_findings"
    __table_args__ = (UniqueConstraint("cloud", "resource_id", name="uq_finops_finding_resource"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    cloud: Mapped[str] = mapped_column(String(8), index=True)
    scope: Mapped[str] = mapped_column(String(256), index=True)
    region: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(16))
    resource_type: Mapped[str] = mapped_column(String(128))
    resource_id: Mapped[str] = mapped_column(String(1024))
    name: Mapped[str] = mapped_column(String(512))
    missing_json: Mapped[str] = mapped_column(Text)       # required tags absent
    wrong_case_json: Mapped[str] = mapped_column(Text)    # present only with different case
    invalid_json: Mapped[str] = mapped_column(Text)       # present but empty / not an allowed value
    owner_hint: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(16), index=True)  # OPEN | RESOLVED
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_scan_id: Mapped[str] = mapped_column(String(36))


class OptimizationCandidateRow(Base):
    """A resource observed as idle (e.g. an unattached disk) and since when."""

    __tablename__ = "finops_optimization_candidates"
    __table_args__ = (UniqueConstraint("cloud", "resource_id", name="uq_finops_candidate_resource"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    cloud: Mapped[str] = mapped_column(String(8))
    kind: Mapped[str] = mapped_column(String(32))          # ebs_volume | elastic_ip | azure_disk | gcp_disk
    resource_id: Mapped[str] = mapped_column(String(1024))
    payload_json: Mapped[str] = mapped_column(Text)
    monthly_cost_hint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_idle_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_idle_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    proposal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
