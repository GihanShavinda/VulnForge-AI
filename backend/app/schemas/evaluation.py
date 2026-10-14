from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EvaluationFindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_ref: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    kev: bool
    epss: float = Field(ge=0.0, le=1.0)
    environmental_score: float = Field(ge=0.0, le=100.0)
    expert_rank: int = Field(ge=1)
    predicted_applicable: bool
    applicable: bool
    attack_path_relevant: bool
    triage_seconds: float = Field(ge=0.0)
    pre_remediation_risk: float = Field(ge=0.0, le=100.0)
    post_remediation_risk: float = Field(ge=0.0, le=100.0)
    ai_factual_correct: bool
    ai_unsupported_claim: bool
    security_rule_correct: bool
    verification_success: bool


class EvaluationRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment_name: str = "VMware VulnForge Laboratory"
    dataset_name: str
    notes: str | None = None
    findings: list[EvaluationFindingInput] = Field(min_length=1)
    top_k: int = Field(default=5, ge=1)


class EvaluationRunRead(ORMModel):
    id: uuid.UUID
    environment_name: str
    dataset_name: str
    notes: str | None
    experiment_table: list
    metrics: dict
    created_at: datetime
