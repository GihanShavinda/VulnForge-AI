from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(120), nullable=False)
    subtechnique_of: Mapped[str | None] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class WeaknessCapecMapping(Base):
    __tablename__ = "weakness_capec_mappings"
    __table_args__ = (
        UniqueConstraint("cwe_id", "capec_id", name="uq_weakness_capec"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cwe_id: Mapped[str] = mapped_column(String(32), nullable=False)
    capec_id: Mapped[str] = mapped_column(String(32), nullable=False)
    capec_name: Mapped[str] = mapped_column(String(255), nullable=False)
    mapping_confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    mapping_source: Mapped[str] = mapped_column(String(255), nullable=False)
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class WeaknessTechniqueMapping(Base):
    __tablename__ = "weakness_technique_mappings"
    __table_args__ = (
        UniqueConstraint("subject_type", "subject_id", "attack_id", name="uq_weakness_technique"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    attack_id: Mapped[str] = mapped_column(String(32), nullable=False)
    context_type: Mapped[str] = mapped_column(String(32), nullable=False, default="potential")
    mapping_confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    mapping_source: Mapped[str] = mapped_column(String(255), nullable=False)
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class BehaviourObservation(Base):
    __tablename__ = "behaviour_observations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_id: Mapped[str | None] = mapped_column(String(128))
    attack_id: Mapped[str] = mapped_column(String(32), nullable=False)
    context_type: Mapped[str] = mapped_column(String(32), nullable=False)
    mapping_confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    mapping_source: Mapped[str] = mapped_column(String(255), nullable=False)
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
