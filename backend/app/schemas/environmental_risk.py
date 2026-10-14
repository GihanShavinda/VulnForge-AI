from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


FACTOR_NAMES = (
    "technical_severity",
    "exploit_probability",
    "known_exploitation",
    "network_exposure",
    "service_reachability",
    "asset_criticality",
    "attack_path_importance",
    "privilege_impact",
    "credential_exposure",
    "security_control_weakness",
    "patch_unavailability",
    "threat_relevance",
    "evidence_confidence",
    "lifecycle_risk",
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EnvironmentalRiskFactors(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technical_severity_cvss: float = Field(ge=0.0, le=10.0)
    exploit_probability: float = Field(ge=0.0, le=1.0)
    known_exploitation: bool

    network_exposure: str
    service_reachability: str
    asset_criticality: str
    attack_path_importance: str
    privilege_impact: str
    credential_exposure: str
    security_control_strength: str
    patch_availability: str
    threat_relevance: str
    evidence_confidence: str
    lifecycle_risk: str

    @field_validator(
        "network_exposure",
        "service_reachability",
        "asset_criticality",
        "attack_path_importance",
        "privilege_impact",
        "credential_exposure",
        "security_control_strength",
        "patch_availability",
        "threat_relevance",
        "evidence_confidence",
        "lifecycle_risk",
    )
    @classmethod
    def normalize_text(cls, value: str) -> str:
        return value.strip().lower()


class RiskScoreVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version_key: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    experimental: bool = True
    active: bool = True
    weights: dict[str, float]
    interaction_rules: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_weights(self):
        missing = [name for name in FACTOR_NAMES if name not in self.weights]
        extra = [name for name in self.weights if name not in FACTOR_NAMES]

        if missing:
            raise ValueError(f"Missing weights: {', '.join(missing)}")
        if extra:
            raise ValueError(f"Unsupported weights: {', '.join(extra)}")

        for name, weight in self.weights.items():
            if weight < 0:
                raise ValueError(f"Weight cannot be negative: {name}")

        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0; received {total:.6f}")

        return self


class EnvironmentalRiskScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID | None = None
    vulnerability_id: str | None = Field(default=None, max_length=128)
    calculation_version: str = Field(default="ers-2.0-experimental", max_length=64)
    factors: EnvironmentalRiskFactors


class RiskScoreVersionRead(ORMModel):
    id: uuid.UUID
    version_key: str
    name: str
    description: str
    experimental: bool
    active: bool
    weights: dict
    interaction_rules: dict
    created_at: datetime


class EnvironmentalRiskContributionRead(ORMModel):
    id: uuid.UUID
    score_id: uuid.UUID
    factor_name: str
    contribution_type: str
    raw_value: str
    normalized_value: float | None
    configured_weight: float | None
    contribution: float
    reason: str
    sequence: int


class EnvironmentalRiskScoreRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    vulnerability_id: str | None
    score_version_id: uuid.UUID
    calculation_version: str
    raw_factors: dict
    normalized_factors: dict
    weights: dict
    base_score: float
    interaction_adjustment: float
    final_score: float
    priority_tier: str
    experimental: bool
    rationale: str
    created_at: datetime


class EnvironmentalRiskScoreResult(BaseModel):
    score: EnvironmentalRiskScoreRead
    contributions: list[EnvironmentalRiskContributionRead]
