from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SbomImport(Base):
    __tablename__ = "sbom_imports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    component_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    components: Mapped[list["PackageComponent"]] = relationship(back_populates="sbom_import", cascade="all, delete-orphan")
    matches: Mapped[list["PackageVulnerabilityMatch"]] = relationship(back_populates="sbom_import", cascade="all, delete-orphan")


class PackageComponent(Base):
    __tablename__ = "package_components"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sbom_import_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sbom_imports.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    version: Mapped[str | None] = mapped_column(String(255))
    ecosystem: Mapped[str | None] = mapped_column(String(80))
    purl: Mapped[str | None] = mapped_column(String(1024))
    cpe: Mapped[str | None] = mapped_column(String(1024))
    supplier: Mapped[str | None] = mapped_column(String(512))
    package_origin: Mapped[str | None] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    vendor_status: Mapped[str | None] = mapped_column(String(64))
    evidence_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    identity_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    sbom_import: Mapped["SbomImport"] = relationship(back_populates="components")
    matches: Mapped[list["PackageVulnerabilityMatch"]] = relationship(back_populates="component", cascade="all, delete-orphan")


class VulnerabilityAdvisory(Base):
    __tablename__ = "vulnerability_advisories"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    ecosystem: Mapped[str | None] = mapped_column(String(80))
    package_name: Mapped[str | None] = mapped_column(String(512))
    purl: Mapped[str | None] = mapped_column(String(1024))
    cpe: Mapped[str | None] = mapped_column(String(1024))
    affected_range: Mapped[str | None] = mapped_column(String(1024))
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    version_scheme: Mapped[str] = mapped_column(String(32), nullable=False, default="generic")
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="high confidence")
    evidence_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class PackageVulnerabilityMatch(Base):
    __tablename__ = "package_vulnerability_matches"
    __table_args__ = (
        UniqueConstraint("component_id", "vulnerability_id", "match_source", name="uq_component_vuln_source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sbom_import_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sbom_imports.id", ondelete="CASCADE"), nullable=False)
    component_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("package_components.id", ondelete="CASCADE"), nullable=False)
    advisory_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("vulnerability_advisories.id", ondelete="SET NULL"))
    vulnerability_id: Mapped[str] = mapped_column(String(128), nullable=False)
    match_source: Mapped[str] = mapped_column(String(80), nullable=False)
    match_method: Mapped[str] = mapped_column(String(64), nullable=False)
    version_evidence: Mapped[str] = mapped_column(String(1024), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    affected_range: Mapped[str | None] = mapped_column(String(1024))
    package_origin: Mapped[str | None] = mapped_column(String(512))
    evidence_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    sbom_import: Mapped["SbomImport"] = relationship(back_populates="matches")
    component: Mapped["PackageComponent"] = relationship(back_populates="matches")


class ComponentDriftEvent(Base):
    __tablename__ = "component_drift_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    previous_import_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sbom_imports.id", ondelete="SET NULL"))
    current_import_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sbom_imports.id", ondelete="CASCADE"), nullable=False)
    identity_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_version: Mapped[str | None] = mapped_column(String(255))
    current_version: Mapped[str | None] = mapped_column(String(255))
    evidence_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
