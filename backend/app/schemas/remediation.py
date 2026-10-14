from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


WorkflowState = Literal[
    "Open",
    "Triaged",
    "Assigned",
    "Remediation In Progress",
    "Ready for Verification",
    "Verified",
    "Closed",
    "Accepted Risk",
    "False Positive",
    "Deferred",
]

PRIMARY_FLOW = [
    "Open",
    "Triaged",
    "Assigned",
    "Remediation In Progress",
    "Ready for Verification",
    "Verified",
    "Closed",
]

ALTERNATIVE_STATES = {
    "Accepted Risk",
    "False Positive",
    "Deferred",
}


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RemediationCaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_ref: str = Field(min_length=1, max_length=160)
    finding_type: str = Field(min_length=1, max_length=64)
    vulnerability_id: str | None = Field(default=None, max_length=128)
    root_cause: str = Field(min_length=1)
    technical_remediation: str = Field(min_length=1)
    temporary_mitigation: str | None = None
    affected_assets: list[str] = Field(min_length=1)
    owner: str = Field(min_length=1, max_length=255)
    sla_days: int = Field(ge=0, le=3650)
    priority: Literal["P0", "P1", "P2", "P3", "P4"]
    due_date: date
    verification_procedure: str = Field(min_length=1)
    rollback_notes: str | None = None
    expected_risk_reduction: float = Field(ge=0.0, le=100.0)


class RemediationCaseRead(ORMModel):
    id: uuid.UUID
    finding_ref: str
    finding_type: str
    vulnerability_id: str | None
    root_cause: str
    technical_remediation: str
    temporary_mitigation: str | None
    affected_assets: list
    owner: str
    sla_days: int
    priority: str
    due_date: date
    verification_procedure: str
    rollback_notes: str | None
    expected_risk_reduction: float
    status: str
    risk_acceptance_reason: str | None
    deferral_reason: str | None
    false_positive_reason: str | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class StatusTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_status: WorkflowState
    actor: str = Field(min_length=1, max_length=255)
    reason: str | None = None

    @model_validator(mode="after")
    def require_alternative_reason(self):
        if self.to_status in ALTERNATIVE_STATES and not self.reason:
            raise ValueError(f"Reason is required for {self.to_status}.")
        return self


class RemediationEvidenceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_stage: Literal["before", "during", "after", "closure"]
    evidence_type: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=255)
    content: dict
    confidence: Literal["confirmed", "high", "medium", "low", "unknown"]


class RemediationEvidenceRead(ORMModel):
    id: uuid.UUID
    case_id: uuid.UUID
    evidence_stage: str
    evidence_type: str
    source: str
    content: dict
    confidence: str
    created_at: datetime


class ReassessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    before_evidence: dict
    after_evidence: dict
    before_score: float = Field(ge=0.0, le=100.0)
    after_score: float = Field(ge=0.0, le=100.0)
    before_attack_path: dict = Field(default_factory=dict)
    after_attack_path: dict = Field(default_factory=dict)
    before_controls: list[dict] = Field(default_factory=list)
    after_controls: list[dict] = Field(default_factory=list)


class ReassessmentRead(ORMModel):
    id: uuid.UUID
    case_id: uuid.UUID
    before_evidence: dict
    after_evidence: dict
    before_score: float
    after_score: float
    risk_delta: float
    before_attack_path: dict
    after_attack_path: dict
    attack_path_change: str
    before_controls: list
    after_controls: list
    control_change: dict
    verification_success: bool
    regression_detected: bool
    regression_reasons: list
    created_at: datetime


class RemediationCaseDetail(BaseModel):
    case: RemediationCaseRead
    evidence: list[RemediationEvidenceRead]
    reassessments: list[ReassessmentRead]
