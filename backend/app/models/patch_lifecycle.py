from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PatchLifecycleAssessmentRun(Base):
    __tablename__ = "patch_lifecycle_assessment_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    patch_finding_count: Mapped[int] = mapped_column(nullable=False, default=0)
    lifecycle_finding_count: Mapped[int] = mapped_column(nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class PatchFinding(Base):
    __tablename__ = "patch_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("patch_lifecycle_assessment_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    component: Mapped[str] = mapped_column(String(255), nullable=False)
    installed_version: Mapped[str | None] = mapped_column(String(255))
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    vulnerability_id: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_state: Mapped[str] = mapped_column(String(64), nullable=False)
    patch_available: Mapped[bool | None] = mapped_column(Boolean)
    vendor_backport: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reboot_required: Mapped[bool | None] = mapped_column(Boolean)
    compensating_control: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class LifecycleFinding(Base):
    __tablename__ = "lifecycle_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("patch_lifecycle_assessment_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    vendor_support_status: Mapped[str] = mapped_column(String(64), nullable=False)
    end_of_support_date: Mapped[date | None] = mapped_column(Date)
    patch_availability: Mapped[str] = mapped_column(String(64), nullable=False)
    accepted_legacy_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    temporary_compensating_control: Mapped[str | None] = mapped_column(Text)
    vendor_backport: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    replacement_recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
