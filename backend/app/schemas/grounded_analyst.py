from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


EvidenceType = Literal[
    "asset", "service", "confirmed_version", "cve", "cwe", "capec", "cvss",
    "kev", "epss", "reachability", "configuration_state", "security_control",
    "attack_path", "patch_information", "lifecycle_information",
    "evidence_confidence", "business_context", "attack_mapping",
    "scanner_text", "http_page_content", "package_description",
    "cve_description", "imported_report_text",
]

UNTRUSTED_TEXT_TYPES = {
    "scanner_text",
    "http_page_content",
    "package_description",
    "cve_description",
    "imported_report_text",
}


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class StructuredEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=128)
    evidence_type: EvidenceType
    source: str = Field(min_length=1, max_length=255)
    confidence: Literal["confirmed", "high", "medium", "low", "unknown"] = "unknown"
    data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_id")
    @classmethod
    def normalize_id(cls, value: str) -> str:
        return value.strip()


class GroundedAnalystRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence: list[StructuredEvidence] = Field(min_length=1)
    calculation_version: str = Field(default="grounded-analyst-1.0", max_length=64)

    @field_validator("evidence")
    @classmethod
    def unique_evidence_ids(cls, value: list[StructuredEvidence]) -> list[StructuredEvidence]:
        ids = [item.evidence_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence_id values must be unique.")
        return value


class EvidenceBackedStatement(BaseModel):
    text: str
    evidence_ids: list[str] = Field(min_length=1)


class EvidenceView(BaseModel):
    evidence_id: str
    evidence_type: str
    source: str
    confidence: str


class GroundedAnalystOutput(BaseModel):
    executive_summary: EvidenceBackedStatement
    technical_summary: EvidenceBackedStatement
    exploitability: EvidenceBackedStatement
    evidence: list[EvidenceView]
    attack_path_effect: EvidenceBackedStatement
    business_impact: EvidenceBackedStatement
    recommended_actions: list[EvidenceBackedStatement]
    verification_steps: list[EvidenceBackedStatement]
    confidence: EvidenceBackedStatement
    unknowns: list[EvidenceBackedStatement]


class GroundedAnalystRunRead(ORMModel):
    id: uuid.UUID
    calculation_version: str
    model_name: str
    fallback_used: bool
    input_evidence: list
    output_json: dict
    grounding_status: str
    created_at: datetime


class GroundedAnalystResponse(BaseModel):
    run: GroundedAnalystRunRead
    analysis: GroundedAnalystOutput
