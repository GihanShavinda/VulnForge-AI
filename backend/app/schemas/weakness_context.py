from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AttackTechniqueRead(ORMModel):
    id: uuid.UUID
    attack_id: str
    name: str
    tactic: str
    subtechnique_of: str | None
    source: str
    source_url: str | None


class CapecContext(BaseModel):
    capec_id: str
    capec_name: str
    mapping_confidence: str
    mapping_source: str
    mapping_rationale: str
    source_url: str | None


class WeaknessContext(BaseModel):
    cwe_id: str
    intelligence_sources: list[str]
    capec: list[CapecContext]


class TechniqueContext(BaseModel):
    attack_id: str
    name: str
    tactic: str
    subtechnique_of: str | None
    context_type: str
    mapping_confidence: str
    mapping_source: str
    mapping_rationale: str


class VulnerabilityContextResponse(BaseModel):
    canonical_id: str
    security_weaknesses: list[WeaknessContext]
    possible_attacker_behaviour: list[TechniqueContext]
    observed_or_confirmed_behaviour: list[TechniqueContext]
    disclaimer: str




class FindingTechniqueMappingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    attack_id: str = Field(min_length=2, max_length=32)
    mapping_confidence: str = Field(default="medium confidence", max_length=32)
    mapping_source: str = Field(min_length=1, max_length=255)
    mapping_rationale: str = Field(min_length=1)


class FindingTechniqueMappingRead(ORMModel):
    id: uuid.UUID
    subject_type: str
    subject_id: str
    attack_id: str
    context_type: str
    mapping_confidence: str
    mapping_source: str
    mapping_rationale: str
    created_at: datetime


class BehaviourObservationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    canonical_id: str | None = Field(default=None, max_length=128)
    attack_id: str = Field(min_length=2, max_length=32)
    context_type: str
    mapping_confidence: str = Field(default="high confidence", max_length=32)
    mapping_source: str = Field(min_length=1, max_length=255)
    mapping_rationale: str = Field(min_length=1)
    evidence: dict

    @model_validator(mode="after")
    def validate_state(self):
        if self.context_type not in {"observed", "confirmed"}:
            raise ValueError("context_type must be observed or confirmed")
        if not self.evidence:
            raise ValueError("Observed/confirmed behaviour requires non-empty evidence.")
        return self


class BehaviourObservationRead(ORMModel):
    id: uuid.UUID
    finding_id: str
    canonical_id: str | None
    attack_id: str
    context_type: str
    mapping_confidence: str
    mapping_source: str
    mapping_rationale: str
    evidence_json: dict
    created_at: datetime


class FindingContextResponse(BaseModel):
    finding_id: str
    possible_attacker_behaviour: list[TechniqueContext]
    observed_or_confirmed_behaviour: list[TechniqueContext]
    disclaimer: str
