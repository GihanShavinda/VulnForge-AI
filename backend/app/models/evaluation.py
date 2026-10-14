from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    environment_name: Mapped[str] = mapped_column(String(255), nullable=False)
    dataset_name: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    experiment_table: Mapped[list] = mapped_column(JSONB, nullable=False)
    metrics: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class EvaluationFinding(Base):
    __tablename__ = "evaluation_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evaluation_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evaluation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    kev: Mapped[int] = mapped_column(Integer, nullable=False)
    epss: Mapped[float] = mapped_column(Float, nullable=False)
    environmental_score: Mapped[float] = mapped_column(Float, nullable=False)
    expert_rank: Mapped[int] = mapped_column(Integer, nullable=False)
    predicted_applicable: Mapped[int] = mapped_column(Integer, nullable=False)
    applicable: Mapped[int] = mapped_column(Integer, nullable=False)
    attack_path_relevant: Mapped[int] = mapped_column(Integer, nullable=False)
    triage_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    pre_remediation_risk: Mapped[float] = mapped_column(Float, nullable=False)
    post_remediation_risk: Mapped[float] = mapped_column(Float, nullable=False)
    ai_factual_correct: Mapped[int] = mapped_column(Integer, nullable=False)
    ai_unsupported_claim: Mapped[int] = mapped_column(Integer, nullable=False)
    security_rule_correct: Mapped[int] = mapped_column(Integer, nullable=False)
    verification_success: Mapped[int] = mapped_column(Integer, nullable=False)
