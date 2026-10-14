from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationCase(Base):
    __tablename__ = "remediation_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_ref: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    vulnerability_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    technical_remediation: Mapped[str] = mapped_column(Text, nullable=False)
    temporary_mitigation: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_assets: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    sla_days: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[str] = mapped_column(String(8), nullable=False)
    due_date: Mapped[date] = mapped_column(Date, nullable=False)
    verification_procedure: Mapped[str] = mapped_column(Text, nullable=False)
    rollback_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_risk_reduction: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="Open")
    risk_acceptance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    deferral_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RemediationEvidence(Base):
    __tablename__ = "remediation_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_stage: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[dict] = mapped_column(JSONB, nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ReassessmentRun(Base):
    __tablename__ = "reassessment_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    before_evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    after_evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    before_score: Mapped[float] = mapped_column(Float, nullable=False)
    after_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_delta: Mapped[float] = mapped_column(Float, nullable=False)
    before_attack_path: Mapped[dict] = mapped_column(JSONB, nullable=False)
    after_attack_path: Mapped[dict] = mapped_column(JSONB, nullable=False)
    attack_path_change: Mapped[str] = mapped_column(String(64), nullable=False)
    before_controls: Mapped[list] = mapped_column(JSONB, nullable=False)
    after_controls: Mapped[list] = mapped_column(JSONB, nullable=False)
    control_change: Mapped[dict] = mapped_column(JSONB, nullable=False)
    verification_success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    regression_detected: Mapped[bool] = mapped_column(Boolean, nullable=False)
    regression_reasons: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class RemediationStatusEvent(Base):
    __tablename__ = "remediation_status_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    from_status: Mapped[str] = mapped_column(String(64), nullable=False)
    to_status: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
