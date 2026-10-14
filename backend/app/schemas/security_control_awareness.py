from __future__ import annotations
import uuid
from datetime import date, datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator

CONTROL_TYPES = (
    "host_firewall","network_segmentation","authentication_requirement","edr_av","mfa",
    "reverse_proxy","waf","least_privilege","service_disabled","acl","patch","tls",
    "application_allow_listing","restricted_admin_access",
)
EXPOSURE_TYPES = (
    "network_service","web_application","credential_exposure","privilege_escalation",
    "malware_execution","lateral_movement","administrative_access","transport_security",
    "vulnerability_exploitability",
)

class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class SecurityControlCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    control_type: str
    owner: str = Field(min_length=1, max_length=255)
    effectiveness: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=100.0)
    evidence: dict = Field(default_factory=dict)
    temporary: bool = False
    effective_from: date | None = None
    expires_at: date | None = None
    mitigation_until: date | None = None
    enabled: bool = True

    @field_validator("control_type")
    @classmethod
    def validate_control_type(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in CONTROL_TYPES:
            raise ValueError(f"Unsupported control_type: {value}")
        return value

class SecurityControlRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    name: str
    control_type: str
    owner: str
    effectiveness: float
    confidence: float
    evidence: dict
    temporary: bool
    effective_from: date | None
    expires_at: date | None
    mitigation_until: date | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

class ControlRiskAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: uuid.UUID | None = None
    vulnerability_id: str | None = Field(default=None, max_length=128)
    exposure_type: str
    inherent_risk: float = Field(ge=0.0, le=100.0)
    control_ids: list[uuid.UUID] = Field(default_factory=list)
    calculation_version: str = Field(default="control-aware-risk-1.0", max_length=64)

    @field_validator("exposure_type")
    @classmethod
    def validate_exposure_type(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in EXPOSURE_TYPES:
            raise ValueError(f"Unsupported exposure_type: {value}")
        return value

class ControlRiskAssessmentRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    vulnerability_id: str | None
    exposure_type: str
    inherent_risk: float
    combined_control_effectiveness: float
    combined_control_confidence: float
    residual_risk: float
    calculation_version: str
    rationale: str
    created_at: datetime

class ControlRiskContributionRead(ORMModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    control_id: uuid.UUID
    control_type: str
    control_owner: str
    effect: str
    control_effectiveness: float
    control_confidence: float
    effective_mitigation: float
    control_evidence: dict
    expired: bool
    temporary: bool
    expires_at: date | None
    mitigation_until: date | None
    reason: str

class ControlRiskAssessmentResult(BaseModel):
    assessment: ControlRiskAssessmentRead
    contributions: list[ControlRiskContributionRead]
