from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EnumerationJob(Base):
    __tablename__ = "enumeration_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    top_ports: Mapped[int] = mapped_column(Integer, nullable=False)
    scan_source: Mapped[str] = mapped_column(String(64), nullable=False, default="nmap")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    command_args_json: Mapped[str | None] = mapped_column(Text)
    explicitly_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    services: Mapped[list["ServiceObservation"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    evidence: Mapped["EnumerationEvidence | None"] = relationship(
        back_populates="job", uselist=False, cascade="all, delete-orphan"
    )
    findings: Mapped[list["ExposureFinding"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class ServiceObservation(Base):
    __tablename__ = "service_observations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    enumeration_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("enumeration_jobs.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    service: Mapped[str | None] = mapped_column(String(120))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(255))
    banner: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(Text)
    tls_indicator: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scan_confidence: Mapped[int | None] = mapped_column(Integer)
    detection_source: Mapped[str] = mapped_column(String(120), nullable=False, default="nmap-service-probe")
    script_outputs_json: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    change_types: Mapped[str | None] = mapped_column(Text)

    job: Mapped[EnumerationJob] = relationship(back_populates="services")
    findings: Mapped[list["ExposureFinding"]] = relationship(back_populates="service_observation")


class EnumerationEvidence(Base):
    __tablename__ = "enumeration_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    enumeration_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("enumeration_jobs.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="nmap_xml")
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_xml: Mapped[str] = mapped_column(Text, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    job: Mapped[EnumerationJob] = relationship(back_populates="evidence")


class ExposureFinding(Base):
    __tablename__ = "exposure_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    enumeration_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("enumeration_jobs.id", ondelete="CASCADE"), nullable=False
    )
    service_observation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("service_observations.id", ondelete="CASCADE")
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    rule_code: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False, default="exposure")
    severity: Mapped[str] = mapped_column(String(24), nullable=False, default="info")
    conclusion: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    job: Mapped[EnumerationJob] = relationship(back_populates="findings")
    service_observation: Mapped[ServiceObservation | None] = relationship(back_populates="findings")
