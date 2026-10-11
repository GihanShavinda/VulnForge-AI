from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ServiceEnumerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID
    protocol: Literal["tcp", "udp"] = "tcp"
    top_ports: int = Field(default=1000, ge=1, le=2000)
    explicitly_authorized: bool = False


class EnumerationJobRead(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    target: str
    protocol: str
    top_ports: int
    scan_source: str
    status: str
    explicitly_authorized: bool
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime


class ServiceObservationRead(ORMModel):
    id: uuid.UUID
    enumeration_job_id: uuid.UUID
    asset_id: uuid.UUID
    ip_address: str
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None
    banner: str | None
    cpe: str | None
    tls_indicator: bool
    scan_confidence: int | None
    detection_source: str
    first_seen: datetime
    last_seen: datetime
    change_types: str | None


class ExposureFindingRead(ORMModel):
    id: uuid.UUID
    enumeration_job_id: uuid.UUID
    service_observation_id: uuid.UUID | None
    asset_id: uuid.UUID
    rule_code: str
    title: str
    category: str
    severity: str
    conclusion: str
    evidence_json: str
    created_at: datetime


class EnumerationEvidenceRead(ORMModel):
    id: uuid.UUID
    enumeration_job_id: uuid.UUID
    evidence_type: str
    content_sha256: str
    raw_xml: str
    captured_at: datetime


class ServiceEnumerationResult(BaseModel):
    job: EnumerationJobRead
    services: list[ServiceObservationRead]
    findings: list[ExposureFindingRead]
