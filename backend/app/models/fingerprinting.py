from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FingerprintJob(Base):
    __tablename__ = "fingerprint_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    explicitly_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    run_nmap_os: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    run_whatweb: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    collect_http_headers: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    warning_message: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    observations: Mapped[list["TechnologyObservation"]] = relationship(back_populates="job", cascade="all, delete-orphan")
    evidence: Mapped[list["FingerprintEvidence"]] = relationship(back_populates="job", cascade="all, delete-orphan")


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    canonical_key: Mapped[str] = mapped_column(String(300), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(255))
    product_family: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    observations: Mapped[list["TechnologyObservation"]] = relationship(back_populates="technology")


class TechnologyObservation(Base):
    __tablename__ = "technology_observations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fingerprint_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("fingerprint_jobs.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    technology_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("technologies.id", ondelete="RESTRICT"), nullable=False)
    observed_name: Mapped[str] = mapped_column(String(255), nullable=False)
    observed_version: Mapped[str | None] = mapped_column(String(255))
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    conflict_state: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    is_preferred: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_legacy: Mapped[bool | None] = mapped_column(Boolean)
    lifecycle_note: Mapped[str | None] = mapped_column(Text)
    evidence_summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    job: Mapped[FingerprintJob] = relationship(back_populates="observations")
    technology: Mapped[Technology] = relationship(back_populates="observations")
    evidence: Mapped[list["FingerprintEvidence"]] = relationship(back_populates="technology_observation")


class FingerprintEvidence(Base):
    __tablename__ = "fingerprint_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fingerprint_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("fingerprint_jobs.id", ondelete="CASCADE"), nullable=False)
    technology_observation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("technology_observations.id", ondelete="CASCADE"), nullable=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_locator: Mapped[str | None] = mapped_column(String(512))
    observed_value: Mapped[str] = mapped_column(Text, nullable=False)
    version_evidence: Mapped[str | None] = mapped_column(String(255))
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_evidence: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    job: Mapped[FingerprintJob] = relationship(back_populates="evidence")
    technology_observation: Mapped[TechnologyObservation | None] = relationship(back_populates="evidence")
