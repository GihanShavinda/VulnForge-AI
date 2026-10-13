from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ThreatIntelSource(Base):
    __tablename__ = "threat_intel_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    freshness_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)
    cache_namespace: Mapped[str] = mapped_column(String(120), nullable=False)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    etag: Mapped[str | None] = mapped_column(String(512))
    last_modified: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    sync_runs: Mapped[list["IntelSyncRun"]] = relationship(back_populates="source", cascade="all, delete-orphan")
    observations: Mapped[list["ThreatIntelObservation"]] = relationship(back_populates="source", cascade="all, delete-orphan")


class IntelSyncRun(Base):
    __tablename__ = "intel_sync_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_intel_sources.id", ondelete="CASCADE"), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_identifiers: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    fetched_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    normalized_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)

    source: Mapped["ThreatIntelSource"] = relationship(back_populates="sync_runs")


class ThreatIntelObservation(Base):
    __tablename__ = "threat_intel_observations"
    __table_args__ = (
        UniqueConstraint("source_id", "canonical_id", "raw_sha256", name="uq_threat_intel_source_canonical_hash"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_intel_sources.id", ondelete="CASCADE"), nullable=False)
    sync_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("intel_sync_runs.id", ondelete="CASCADE"), nullable=False)
    canonical_id: Mapped[str] = mapped_column(String(128), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(64))
    osv_id: Mapped[str | None] = mapped_column(String(128))
    cwes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    cvss31_score: Mapped[float | None] = mapped_column(Float)
    cvss31_vector: Mapped[str | None] = mapped_column(String(512))
    cvss4_score: Mapped[float | None] = mapped_column(Float)
    cvss4_vector: Mapped[str | None] = mapped_column(String(512))
    cpes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    affected_ranges: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    fixed_ranges: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    references: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev: Mapped[bool | None] = mapped_column(Boolean)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    vendor_advisories: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    known_ransomware_use: Mapped[bool | None] = mapped_column(Boolean)
    required_action: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    source_record_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    source: Mapped["ThreatIntelSource"] = relationship(back_populates="observations")


class IntelConflict(Base):
    __tablename__ = "intel_conflicts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    canonical_id: Mapped[str] = mapped_column(String(128), nullable=False)
    field_name: Mapped[str] = mapped_column(String(120), nullable=False)
    source_values: Mapped[dict] = mapped_column(JSONB, nullable=False)
    resolution_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unresolved")
    resolution_note: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
