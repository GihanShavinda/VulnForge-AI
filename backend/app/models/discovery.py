from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    discovery_method: Mapped[str] = mapped_column(String(32), nullable=False)
    scan_source: Mapped[str] = mapped_column(String(64), nullable=False, default="nmap")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    command_args_json: Mapped[str | None] = mapped_column(Text)
    explicitly_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    hosts: Mapped[list["DiscoveredHost"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    evidence: Mapped["DiscoveryEvidence | None"] = relationship(
        back_populates="job", uselist=False, cascade="all, delete-orphan"
    )


class DiscoveredHost(Base):
    __tablename__ = "discovered_hosts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False
    )
    matched_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(String(32))
    vendor: Mapped[str | None] = mapped_column(String(255))
    reachable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    scan_source: Mapped[str] = mapped_column(String(64), nullable=False, default="nmap")
    scan_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    identity_basis: Mapped[str | None] = mapped_column(String(64))
    change_types: Mapped[str | None] = mapped_column(Text)

    job: Mapped[DiscoveryJob] = relationship(back_populates="hosts")


class DiscoveryEvidence(Base):
    __tablename__ = "discovery_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="nmap_xml")
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_xml: Mapped[str] = mapped_column(Text, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    job: Mapped[DiscoveryJob] = relationship(back_populates="evidence")
