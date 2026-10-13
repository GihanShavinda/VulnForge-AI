from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class SecretImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID | None = None
    source_type: str = Field(min_length=2, max_length=64)
    source_name: str = Field(min_length=1, max_length=512)
    payload: str | dict | list
    allowlisted_hashes: list[str] = Field(default_factory=list, max_length=500)


class SecretScanImportRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    source_type: str
    source_name: str
    status: str
    candidate_count: int
    finding_count: int
    suppressed_count: int
    imported_at: datetime


class SecretExposureRead(ORMModel):
    id: uuid.UUID
    import_id: uuid.UUID
    secret_type: str
    masked_fingerprint: str
    location: str
    evidence_hash: str
    severity: str
    validation_status: str
    first_seen: datetime
    last_seen: datetime


class SecretAttackPathSignalRead(ORMModel):
    id: uuid.UUID
    exposure_id: uuid.UUID
    source_asset_id: uuid.UUID | None
    related_asset_id: uuid.UUID | None
    signal_type: str
    rationale: str
    confidence: str
    created_at: datetime


class SecretImportResult(BaseModel):
    run: SecretScanImportRead
    findings: list[SecretExposureRead]
    suppressed_count: int
