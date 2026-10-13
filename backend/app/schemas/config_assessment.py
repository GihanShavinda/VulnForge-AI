from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class BenchmarkProfileRead(ORMModel):
    id: uuid.UUID
    name: str
    platform: str
    description: str
    controls: list


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str | None = Field(default=None, max_length=128)
    category: str = Field(min_length=1, max_length=120)
    observed_value: str = Field(min_length=1)
    source_locator: str | None = Field(default=None, max_length=512)
    confidence: str = Field(default="high confidence", max_length=32)
    raw: dict = Field(default_factory=dict)


class ConfigAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID
    profile_name: str = Field(min_length=1, max_length=120)
    source_type: str = Field(min_length=1, max_length=64)
    source_name: str = Field(min_length=1, max_length=255)
    evidence: list[EvidenceItem] = Field(min_length=1, max_length=1000)


class ConfigAssessmentRunRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    profile_id: uuid.UUID
    source_type: str
    source_name: str
    status: str
    evidence_count: int
    finding_count: int
    imported_at: datetime


class ConfigEvidenceRead(ORMModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    control_id: str | None
    category: str
    observed_value: str
    source_locator: str | None
    confidence: str
    raw_json: dict
    created_at: datetime


class ConfigurationFindingRead(ORMModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    control: str
    expected_state: str
    observed_state: str
    evidence: dict
    severity: str
    remediation: str
    confidence: str
    framework_reference: list
    created_at: datetime


class ConfigAssessmentResult(BaseModel):
    run: ConfigAssessmentRunRead
    findings: list[ConfigurationFindingRead]
