from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EnvironmentalContext(BaseModel):
    asset_criticality: int = Field(default=50, ge=0, le=100)
    exposure: int = Field(default=50, ge=0, le=100)
    exploit_maturity: int = Field(default=0, ge=0, le=100)
    kev: bool = False
    epss: float | None = Field(default=None, ge=0, le=1)


class SeverityAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_id: str = Field(min_length=1, max_length=128)
    vector: str = Field(min_length=8)
    source: str = Field(min_length=1, max_length=255)
    environmental_context: EnvironmentalContext = Field(default_factory=EnvironmentalContext)


class SeverityAnalysisRead(ORMModel):
    id: uuid.UUID
    canonical_id: str
    original_vector: str
    source: str
    score_version: str
    base_score: float
    severity: str
    parsed_components: dict
    environmental_priority: float
    priority_band: str
    priority_factors: dict
    rationale: str
    calculated_at: datetime


class SeverityComparisonRow(BaseModel):
    canonical_id: str
    cvss_version: str
    cvss_score: float
    cvss_severity: str
    environmental_priority: float
    environmental_priority_band: str
    source: str
    rationale: str


class SeverityComparisonResponse(BaseModel):
    rows: list[SeverityComparisonRow]
    note: str
