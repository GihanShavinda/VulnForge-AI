from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class VulnerabilitySeverityAnalysis(Base):
    __tablename__ = "vulnerability_severity_analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    canonical_id: Mapped[str] = mapped_column(String(128), nullable=False)
    original_vector: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    score_version: Mapped[str] = mapped_column(String(16), nullable=False)
    base_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    parsed_components: Mapped[dict] = mapped_column(JSONB, nullable=False)
    environmental_priority: Mapped[float] = mapped_column(Float, nullable=False)
    priority_band: Mapped[str] = mapped_column(String(32), nullable=False)
    priority_factors: Mapped[dict] = mapped_column(JSONB, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
