from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PatchObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    component: str = Field(min_length=1, max_length=255)
    installed_version: str | None = Field(default=None, max_length=255)
    fixed_version: str | None = Field(default=None, max_length=255)
    vulnerability_id: str | None = Field(default=None, max_length=128)
    severity: str = Field(default="Medium", max_length=32)
    patch_available: bool | None = None
    vendor_backport: bool = False
    reboot_required: bool | None = None
    compensating_control: str | None = None
    evidence: dict = Field(default_factory=dict)


class LifecycleObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product: str = Field(min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=255)
    category: str = Field(min_length=1, max_length=64)
    vendor_support_status: str = Field(min_length=1, max_length=64)
    end_of_support_date: date | None = None
    patch_availability: str = Field(min_length=1, max_length=64)
    accepted_legacy_system: bool = False
    temporary_compensating_control: str | None = None
    vendor_backport: bool = False
    replacement_recommendation: str = Field(min_length=1)
    evidence: dict = Field(default_factory=dict)


class PatchLifecycleAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID | None = None
    source_name: str = Field(min_length=1, max_length=255)
    patch_observations: list[PatchObservation] = Field(default_factory=list, max_length=2000)
    lifecycle_observations: list[LifecycleObservation] = Field(default_factory=list, max_length=2000)


class PatchLifecycleRunRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    source_name: str
    status: str
    patch_finding_count: int
    lifecycle_finding_count: int
    created_at: datetime


class PatchFindingRead(ORMModel):
    id: uuid.UUID
    run_id: uuid.UUID
    component: str
    installed_version: str | None
    fixed_version: str | None
    vulnerability_id: str | None
    severity: str
    risk_state: str
    patch_available: bool | None
    vendor_backport: bool
    reboot_required: bool | None
    compensating_control: str | None
    evidence: dict
    remediation: str
    first_seen: datetime


class LifecycleFindingRead(ORMModel):
    id: uuid.UUID
    run_id: uuid.UUID
    product: str
    version: str | None
    category: str
    severity: str
    vendor_support_status: str
    end_of_support_date: date | None
    patch_availability: str
    accepted_legacy_system: bool
    temporary_compensating_control: str | None
    vendor_backport: bool
    replacement_recommendation: str
    evidence: dict
    created_at: datetime


class PatchLifecycleAssessmentResult(BaseModel):
    run: PatchLifecycleRunRead
    patch_findings: list[PatchFindingRead]
    lifecycle_findings: list[LifecycleFindingRead]
