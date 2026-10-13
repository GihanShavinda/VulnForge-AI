from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    username: str = Field(min_length=1, max_length=255)
    protocol: Literal["ssh", "winrm"]
    auth_method: Literal["password"] = "password"
    port: int | None = Field(default=None, ge=1, le=65535)
    secret: str = Field(min_length=1, max_length=4096)
    max_failed_attempts: int = Field(default=3, ge=1, le=10)
    description: str | None = None


class CredentialRotateSecret(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret: str = Field(min_length=1, max_length=4096)


class CredentialRead(ORMModel):
    id: uuid.UUID
    name: str
    username: str | None
    secret_reference: str
    protocol: str
    auth_method: str
    port: int | None
    failed_attempts: int
    max_failed_attempts: int
    lockout_until: datetime | None
    last_used_at: datetime | None
    description: str | None
    enabled: bool
    created_at: datetime


class AuthenticatedScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: uuid.UUID
    credential_profile_id: uuid.UUID
    explicitly_authorized: bool = False


class ImportedEvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str = Field(min_length=1, max_length=80)
    observed_value: str = Field(min_length=1)
    source_locator: str | None = Field(default=None, max_length=512)


class ImportedAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: uuid.UUID
    source_name: str = Field(min_length=1, max_length=120)
    explicitly_authorized: bool = False
    evidence: list[ImportedEvidenceItem] = Field(min_length=1, max_length=100)


class AuthenticatedScanRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    credential_profile_id: uuid.UUID | None
    transport: str
    collection_mode: str
    status: str
    explicitly_authorized: bool
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime


class AuthenticatedEvidenceRead(ORMModel):
    id: uuid.UUID
    authenticated_scan_id: uuid.UUID
    asset_id: uuid.UUID
    category: str
    source_type: str
    source_locator: str | None
    observed_value: str
    confidence: str
    content_sha256: str
    captured_at: datetime


class CredentialUseAuditRead(ORMModel):
    id: uuid.UUID
    credential_profile_id: uuid.UUID
    asset_id: uuid.UUID
    authenticated_scan_id: uuid.UUID | None
    outcome: str
    reason: str | None
    remote_address: str
    created_at: datetime


class AuthenticatedScanResult(BaseModel):
    scan: AuthenticatedScanRead
    evidence: list[AuthenticatedEvidenceRead]


class ComparisonRow(BaseModel):
    subject: str
    unauthenticated_value: str | None
    unauthenticated_confidence: str
    authenticated_value: str | None
    authenticated_confidence: str
    confidence_increased: bool
    note: str


class AuthenticatedComparison(BaseModel):
    scan_id: uuid.UUID
    rows: list[ComparisonRow]
