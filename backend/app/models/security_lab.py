from __future__ import annotations

import uuid
from datetime import datetime, time, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    Time,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


# =============================================================================
# Asset <-> Tag association table
# =============================================================================

asset_tag_link = Table(
    "asset_tag_links",
    Base.metadata,
    Column(
        "asset_id",
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "tag_id",
        UUID(as_uuid=True),
        ForeignKey("asset_tags.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


# =============================================================================
# Network
# =============================================================================


class Network(Base):
    __tablename__ = "networks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        unique=True,
        nullable=False,
    )

    cidr: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
    )

    network_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="host-only",
    )

    approved_for_scanning: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    assets: Mapped[list["Asset"]] = relationship(
        back_populates="network",
    )

    scopes: Mapped[list["ScanScope"]] = relationship(
        back_populates="network",
    )


# =============================================================================
# Asset
# =============================================================================


class Asset(Base):
    __tablename__ = "assets"

    __table_args__ = (
        UniqueConstraint(
            "ip_address",
            name="uq_assets_ip_address",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    network_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "networks.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    ip_address: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    mac_address: Mapped[str | None] = mapped_column(
        String(32),
    )

    vendor: Mapped[str | None] = mapped_column(
        String(255),
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(255),
    )

    role: Mapped[str | None] = mapped_column(
        String(120),
    )

    is_vulnerable_target: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    scanning_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    reachable: Mapped[bool | None] = mapped_column(
        Boolean,
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
    )

    last_discovery_source: Mapped[str | None] = mapped_column(
        String(64),
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    network: Mapped["Network"] = relationship(
        back_populates="assets",
    )

    tags: Mapped[list["AssetTag"]] = relationship(
        secondary=asset_tag_link,
        back_populates="assets",
    )


# =============================================================================
# Scan Scope
# =============================================================================


class ScanScope(Base):
    __tablename__ = "scan_scopes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        unique=True,
        nullable=False,
    )

    network_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "networks.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    cidr: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    require_explicit_authorization: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    maintenance_start: Mapped[time | None] = mapped_column(
        Time(timezone=False),
    )

    maintenance_end: Mapped[time | None] = mapped_column(
        Time(timezone=False),
    )

    timezone_name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="Asia/Colombo",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    network: Mapped["Network"] = relationship(
        back_populates="scopes",
    )


# =============================================================================
# Asset Tag
# =============================================================================


class AssetTag(Base):
    __tablename__ = "asset_tags"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
    )

    assets: Mapped[list["Asset"]] = relationship(
        secondary=asset_tag_link,
        back_populates="tags",
    )


# =============================================================================
# Credential Profile
#
# V5:
# - No plaintext password storage
# - encrypted_secret contains encrypted credential material only
# - secret_reference remains an opaque reference
# - failed authentication attempts are tracked
# - automatic VulnForge-side lockout prevents repeated bad authentication
# =============================================================================


class CredentialProfile(Base):
    __tablename__ = "credential_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        unique=True,
        nullable=False,
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
    )

    # -------------------------------------------------------------------------
    # Existing opaque credential reference
    #
    # Example:
    # enc:v1:1a2b3c4d-....
    #
    # This is NOT the password itself.
    # -------------------------------------------------------------------------
    secret_reference: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    # -------------------------------------------------------------------------
    # V5 encrypted credential value
    #
    # Contains Fernet-encrypted secret material only.
    # Plaintext credentials must never be written to this field.
    # -------------------------------------------------------------------------
    encrypted_secret: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # ssh / winrm / imported
    protocol: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    # password / private_key / imported
    auth_method: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="password",
    )

    # SSH usually 22
    # WinRM HTTP usually 5985
    # WinRM HTTPS usually 5986
    #
    # Nullable because imported-evidence profiles do not require
    # a remote service port.
    port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    # -------------------------------------------------------------------------
    # V5 failed-authentication / lockout protection
    # -------------------------------------------------------------------------

    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    max_failed_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
    )

    lockout_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


# =============================================================================
# Scan Profile
# =============================================================================


class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        unique=True,
        nullable=False,
    )

    scanner_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="nmap",
    )

    timeout_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=900,
    )

    max_concurrency: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=2,
    )

    evidence_retention_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=90,
    )

    require_scope_validation: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    require_authorization: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


# =============================================================================
# Audit Log
# =============================================================================


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    event_type: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
    )

    actor: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="system",
    )

    target: Mapped[str | None] = mapped_column(
        String(500),
    )

    allowed: Mapped[bool | None] = mapped_column(
        Boolean,
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
    )

    details_json: Mapped[str | None] = mapped_column(
        Text,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )