from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ConfidenceLevel = Literal["confirmed", "high confidence", "medium confidence", "low confidence", "unknown"]
TechnologyCategory = Literal["operating_system", "kernel", "web_server", "language", "remote_access", "file_sharing", "database", "application_server", "framework", "other"]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AuthenticatedInventoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: TechnologyCategory
    name: str = Field(min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=255)
    observed_value: str | None = None


class FingerprintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: uuid.UUID
    explicitly_authorized: bool = False
    run_nmap_os: bool = True
    run_whatweb: bool = True
    collect_http_headers: bool = True
    authenticated_inventory: list[AuthenticatedInventoryItem] = Field(default_factory=list)


class FingerprintJobRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    target: str
    status: str
    explicitly_authorized: bool
    run_nmap_os: bool
    run_whatweb: bool
    collect_http_headers: bool
    started_at: datetime | None
    completed_at: datetime | None
    warning_message: str | None
    error_message: str | None
    created_at: datetime


class TechnologyRead(ORMModel):
    id: uuid.UUID
    canonical_key: str
    name: str
    category: str
    vendor: str | None
    product_family: str | None
    created_at: datetime


class TechnologyObservationRead(ORMModel):
    id: uuid.UUID
    fingerprint_job_id: uuid.UUID
    asset_id: uuid.UUID
    technology_id: uuid.UUID
    observed_name: str
    observed_version: str | None
    confidence: str
    conflict_state: str
    is_preferred: bool
    is_legacy: bool | None
    lifecycle_note: str | None
    evidence_summary_json: str
    first_seen: datetime
    last_seen: datetime


class FingerprintEvidenceRead(ORMModel):
    id: uuid.UUID
    fingerprint_job_id: uuid.UUID
    technology_observation_id: uuid.UUID | None
    asset_id: uuid.UUID
    source_type: str
    source_locator: str | None
    observed_value: str
    version_evidence: str | None
    confidence: str
    raw_evidence: str
    content_sha256: str
    captured_at: datetime


class FingerprintResult(BaseModel):
    job: FingerprintJobRead
    observations: list[TechnologyObservationRead]
    evidence_count: int
