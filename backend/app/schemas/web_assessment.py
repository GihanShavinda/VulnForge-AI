from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class WebImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID | None = None
    target_url: str = Field(min_length=4, max_length=2048)
    scanner: str = Field(min_length=2, max_length=64)
    source_name: str = Field(min_length=1, max_length=255)
    payload: str | dict | list


class WebAssessmentImportRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    target_url: str
    scanner: str
    source_name: str
    status: str
    evidence_count: int
    finding_count: int
    duplicate_count: int
    imported_at: datetime


class WebEvidenceRead(ORMModel):
    id: uuid.UUID
    import_id: uuid.UUID
    scanner: str
    rule_id: str | None
    title: str
    severity: str
    method: str | None
    url: str
    parameter: str | None
    request_metadata: dict
    response_metadata: dict
    evidence_text: str | None
    raw_redacted: dict
    dedupe_key: str
    created_at: datetime


class WebFindingRead(ORMModel):
    id: uuid.UUID
    import_id: uuid.UUID
    evidence_id: uuid.UUID
    finding_type: str
    title: str
    severity: str
    confidence: str
    description: str
    remediation: str
    owasp_top10: list
    mapping_rationale: str
    created_at: datetime


class WebImportResult(BaseModel):
    run: WebAssessmentImportRead
    findings: list[WebFindingRead]
    duplicates_skipped: int
