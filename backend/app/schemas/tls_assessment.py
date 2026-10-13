from __future__ import annotations
import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class TLSEvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str = Field(min_length=1, max_length=128)
    observed_value: str = Field(min_length=1)
    source_locator: str | None = Field(default=None, max_length=512)
    confidence: str = Field(default="high confidence", max_length=32)
    raw: dict = Field(default_factory=dict)

class TLSAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: uuid.UUID | None = None
    target: str = Field(min_length=1, max_length=512)
    port: int = Field(default=443, ge=1, le=65535)
    scanner: str = Field(min_length=2, max_length=64)
    source_name: str = Field(min_length=1, max_length=255)
    lab_context: bool = False
    evidence: list[TLSEvidenceItem] = Field(min_length=1, max_length=2000)

class TLSScannerParseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scanner: str = Field(min_length=2, max_length=64)
    payload: str | dict | list

class TLSAssessmentImportRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    target: str
    port: int
    scanner: str
    source_name: str
    status: str
    evidence_count: int
    finding_count: int
    lab_context: bool
    imported_at: datetime

class TLSEvidenceRead(ORMModel):
    id: uuid.UUID
    import_id: uuid.UUID
    category: str
    observed_value: str
    source_locator: str | None
    confidence: str
    raw_json: dict
    created_at: datetime

class CryptoFindingRead(ORMModel):
    id: uuid.UUID
    import_id: uuid.UUID
    finding_type: str
    control: str
    observed_state: str
    evidence: dict
    severity: str
    remediation: str
    confidence: str
    acceptable_lab_configuration: bool
    rationale: str
    created_at: datetime

class TLSAssessmentResult(BaseModel):
    run: TLSAssessmentImportRead
    findings: list[CryptoFindingRead]
