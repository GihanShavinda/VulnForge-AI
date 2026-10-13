from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ThreatIntelSourceRead(ORMModel):
    id: uuid.UUID
    name: str
    source_type: str
    base_url: str
    enabled: bool
    freshness_minutes: int
    cache_namespace: str
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None


class IntelSyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    identifiers: list[str] = Field(default_factory=list, max_length=500)
    offline: bool = False
    allow_cache_fallback: bool = True


class IntelSyncRunRead(ORMModel):
    id: uuid.UUID
    source_id: uuid.UUID
    mode: str
    status: str
    requested_identifiers: list
    fetched_count: int
    normalized_count: int
    cache_used: bool
    started_at: datetime
    completed_at: datetime | None
    error_message: str | None


class ThreatIntelObservationRead(ORMModel):
    id: uuid.UUID
    source_id: uuid.UUID
    sync_run_id: uuid.UUID
    canonical_id: str
    cve_id: str | None
    osv_id: str | None
    cwes: list
    cvss31_score: float | None
    cvss31_vector: str | None
    cvss4_score: float | None
    cvss4_vector: str | None
    cpes: list
    affected_ranges: list
    fixed_ranges: list
    references: list
    published_at: datetime | None
    modified_at: datetime | None
    kev: bool | None
    epss: float | None
    epss_percentile: float | None
    vendor_advisories: list
    known_ransomware_use: bool | None
    required_action: str | None
    confidence: str
    raw_sha256: str
    source_record_modified_at: datetime | None
    observed_at: datetime


class IntelConflictRead(ORMModel):
    id: uuid.UUID
    canonical_id: str
    field_name: str
    source_values: dict
    resolution_state: str
    resolution_note: str | None
    detected_at: datetime
    updated_at: datetime


class ThreatIntelObservationView(BaseModel):
    observation: ThreatIntelObservationRead
    source: str
    last_refresh: datetime | None
    stale: bool
    staleness_seconds: int | None
    confidence: str


class ThreatIntelDetail(BaseModel):
    canonical_id: str
    observations: list[ThreatIntelObservationView]
    conflicts: list[IntelConflictRead]


class IntelSyncResult(BaseModel):
    run: IntelSyncRunRead
    observations: list[ThreatIntelObservationRead]
