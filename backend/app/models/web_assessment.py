from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class WebAssessmentImport(Base):
    __tablename__ = "web_assessment_imports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"))
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_count: Mapped[int] = mapped_column(nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(nullable=False, default=0)
    duplicate_count: Mapped[int] = mapped_column(nullable=False, default=0)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class WebEvidence(Base):
    __tablename__ = "web_evidence"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_web_evidence_dedupe_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    import_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("web_assessment_imports.id", ondelete="CASCADE"), nullable=False)
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    method: Mapped[str | None] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    parameter: Mapped[str | None] = mapped_column(String(255))
    request_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False)
    response_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False)
    evidence_text: Mapped[str | None] = mapped_column(Text)
    raw_redacted: Mapped[dict] = mapped_column(JSONB, nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class WebFinding(Base):
    __tablename__ = "web_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    import_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("web_assessment_imports.id", ondelete="CASCADE"), nullable=False)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("web_evidence.id", ondelete="CASCADE"), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    owasp_top10: Mapped[list] = mapped_column(JSONB, nullable=False)
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
