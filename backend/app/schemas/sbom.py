from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class SbomImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: uuid.UUID
    format: str = Field(min_length=2, max_length=32)
    source_name: str = Field(min_length=1, max_length=255)
    document: dict[str, Any] | list[Any] | None = None
    raw_text: str | None = None

    @model_validator(mode="after")
    def require_payload(self):
        if self.document is None and not self.raw_text:
            raise ValueError("Either document or raw_text is required.")
        return self


class AdvisoryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vulnerability_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=80)
    ecosystem: str | None = Field(default=None, max_length=80)
    package_name: str | None = Field(default=None, max_length=512)
    purl: str | None = Field(default=None, max_length=1024)
    cpe: str | None = Field(default=None, max_length=1024)
    affected_range: str | None = Field(default=None, max_length=1024)
    fixed_version: str | None = Field(default=None, max_length=255)
    version_scheme: str = Field(default="generic", max_length=32)
    confidence: str = Field(default="high confidence", max_length=32)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_identity(self):
        if not self.purl and not self.cpe and not (self.ecosystem and self.package_name):
            raise ValueError("Advisory needs an exact PURL, exact CPE, or ecosystem + package_name.")
        return self


class SbomImportRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    format: str
    source_name: str
    source_sha256: str
    status: str
    component_count: int
    vulnerability_count: int
    error_message: str | None
    imported_at: datetime


class PackageComponentRead(ORMModel):
    id: uuid.UUID
    sbom_import_id: uuid.UUID
    asset_id: uuid.UUID
    name: str
    version: str | None
    ecosystem: str | None
    purl: str | None
    cpe: str | None
    supplier: str | None
    package_origin: str | None
    source: str
    vendor_status: str | None
    evidence_json: dict
    identity_key: str
    fingerprint_sha256: str
    created_at: datetime


class VulnerabilityAdvisoryRead(ORMModel):
    id: uuid.UUID
    vulnerability_id: str
    source: str
    ecosystem: str | None
    package_name: str | None
    purl: str | None
    cpe: str | None
    affected_range: str | None
    fixed_version: str | None
    version_scheme: str
    confidence: str
    evidence_json: dict
    created_at: datetime


class PackageVulnerabilityMatchRead(ORMModel):
    id: uuid.UUID
    sbom_import_id: uuid.UUID
    component_id: uuid.UUID
    advisory_id: uuid.UUID | None
    vulnerability_id: str
    match_source: str
    match_method: str
    version_evidence: str
    confidence: str
    fixed_version: str | None
    affected_range: str | None
    package_origin: str | None
    evidence_json: dict
    created_at: datetime


class ComponentDriftRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    previous_import_id: uuid.UUID | None
    current_import_id: uuid.UUID
    identity_key: str
    change_type: str
    previous_version: str | None
    current_version: str | None
    evidence_json: dict
    created_at: datetime


class SbomImportResult(BaseModel):
    sbom_import: SbomImportRead
    components: list[PackageComponentRead]
    matches: list[PackageVulnerabilityMatchRead]
    drift: list[ComponentDriftRead]
