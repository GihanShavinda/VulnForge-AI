from __future__ import annotations
import uuid
from datetime import date, datetime, timezone
from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class SecurityControl(Base):
    __tablename__ = "security_controls"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    control_type: Mapped[str] = mapped_column(String(64), nullable=False)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    effectiveness: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    temporary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    effective_from: Mapped[date | None] = mapped_column(Date, nullable=True)
    expires_at: Mapped[date | None] = mapped_column(Date, nullable=True)
    mitigation_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

class ControlRiskAssessment(Base):
    __tablename__ = "control_risk_assessments"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    exposure_type: Mapped[str] = mapped_column(String(64), nullable=False)
    inherent_risk: Mapped[float] = mapped_column(Float, nullable=False)
    combined_control_effectiveness: Mapped[float] = mapped_column(Float, nullable=False)
    combined_control_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    residual_risk: Mapped[float] = mapped_column(Float, nullable=False)
    calculation_version: Mapped[str] = mapped_column(String(64), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

class ControlRiskContribution(Base):
    __tablename__ = "control_risk_contributions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("control_risk_assessments.id", ondelete="CASCADE"), nullable=False)
    control_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("security_controls.id", ondelete="RESTRICT"), nullable=False)
    control_type: Mapped[str] = mapped_column(String(64), nullable=False)
    control_owner: Mapped[str] = mapped_column(String(255), nullable=False)
    effect: Mapped[str] = mapped_column(String(32), nullable=False)
    control_effectiveness: Mapped[float] = mapped_column(Float, nullable=False)
    control_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    effective_mitigation: Mapped[float] = mapped_column(Float, nullable=False)
    control_evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    expired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    temporary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[date | None] = mapped_column(Date, nullable=True)
    mitigation_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
