from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, time

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class NetworkCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    cidr: str
    network_type: str = Field(default="host-only", max_length=32)
    approved_for_scanning: bool = False
    description: str | None = None

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        return str(ipaddress.ip_network(value, strict=False))


class NetworkRead(ORMModel):
    id: uuid.UUID
    name: str
    cidr: str
    network_type: str
    approved_for_scanning: bool
    description: str | None
    created_at: datetime


class AssetCreate(BaseModel):
    network_id: uuid.UUID
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str
    mac_address: str | None = None
    vendor: str | None = None
    operating_system: str | None = None
    role: str | None = None
    is_vulnerable_target: bool = False
    scanning_enabled: bool = True
    notes: str | None = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))


class AssetRead(ORMModel):
    id: uuid.UUID
    network_id: uuid.UUID
    hostname: str
    ip_address: str
    mac_address: str | None
    vendor: str | None
    operating_system: str | None
    role: str | None
    is_vulnerable_target: bool
    scanning_enabled: bool
    reachable: bool | None
    first_seen: datetime | None
    last_seen: datetime | None
    last_discovery_source: str | None
    notes: str | None
    created_at: datetime
    updated_at: datetime


class ScanScopeCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    network_id: uuid.UUID
    cidr: str
    enabled: bool = True
    require_explicit_authorization: bool = True
    maintenance_start: time | None = None
    maintenance_end: time | None = None
    timezone_name: str = "Asia/Colombo"

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        return str(ipaddress.ip_network(value, strict=False))


class ScanScopeRead(ORMModel):
    id: uuid.UUID
    name: str
    network_id: uuid.UUID
    cidr: str
    enabled: bool
    require_explicit_authorization: bool
    maintenance_start: time | None
    maintenance_end: time | None
    timezone_name: str
    created_at: datetime


class AssetTagCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str | None = None


class AssetTagRead(ORMModel):
    id: uuid.UUID
    name: str
    description: str | None


class CredentialProfileCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    username: str | None = Field(default=None, max_length=255)
    secret_reference: str = Field(min_length=1, max_length=500)
    protocol: str = Field(min_length=1, max_length=32)
    description: str | None = None
    enabled: bool = True


class CredentialProfileRead(ORMModel):
    id: uuid.UUID
    name: str
    username: str | None
    secret_reference: str
    protocol: str
    description: str | None
    enabled: bool
    created_at: datetime


class ScanProfileCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    scanner_type: str = Field(default="nmap", max_length=64)
    timeout_seconds: int = Field(default=900, ge=5, le=86400)
    max_concurrency: int = Field(default=2, ge=1, le=32)
    evidence_retention_days: int = Field(default=90, ge=1, le=3650)
    require_scope_validation: bool = True
    require_authorization: bool = True
    enabled: bool = True
    description: str | None = None


class ScanProfileRead(ORMModel):
    id: uuid.UUID
    name: str
    scanner_type: str
    timeout_seconds: int
    max_concurrency: int
    evidence_retention_days: int
    require_scope_validation: bool
    require_authorization: bool
    enabled: bool
    description: str | None
    created_at: datetime


class AuditLogRead(ORMModel):
    id: uuid.UUID
    event_type: str
    actor: str
    target: str | None
    allowed: bool | None
    reason: str | None
    details_json: str | None
    created_at: datetime


class ScopeValidationRequest(BaseModel):
    target: str
    explicitly_authorized: bool = False


class ScopeValidationResponse(BaseModel):
    target: str
    normalized_target: str | None
    allowed: bool
    matched_scope: str | None = None
    reason: str
