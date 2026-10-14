from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


NODE_LABELS = (
    "Network",
    "Asset",
    "Service",
    "Application",
    "Account",
    "Credential",
    "Vulnerability",
    "ConfigFinding",
    "SecretFinding",
    "SecurityControl",
    "SensitiveAsset",
    "UserRole",
    "TrustBoundary",
)

RELATIONSHIP_TYPES = (
    "CONNECTED_TO",
    "EXPOSES",
    "RUNS",
    "HAS_VULNERABILITY",
    "USES_ACCOUNT",
    "HAS_CREDENTIAL",
    "CAN_ACCESS",
    "TRUSTS",
    "REACHABLE_FROM",
    "PROTECTED_BY",
    "ENABLES",
    "AFFECTS",
    "MEMBER_OF",
    "AUTHENTICATES_TO",
)

SCENARIOS = (
    "internet",
    "kali_lab_attacker",
    "low_privilege_internal_user",
    "compromised_workstation",
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class GraphNodeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=255)
    label: str
    name: str = Field(min_length=1, max_length=255)
    properties: dict = Field(default_factory=dict)


class GraphEdgeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_key: str = Field(min_length=1, max_length=255)
    target_key: str = Field(min_length=1, max_length=255)
    relationship_type: str
    evidence_status: Literal["confirmed", "supported", "theoretical", "unknown"] = "theoretical"
    confidence: Literal[
        "confirmed",
        "high confidence",
        "medium confidence",
        "low confidence",
        "unknown",
    ] = "unknown"
    source: str = Field(default="user-supplied evidence", max_length=255)
    details: dict = Field(default_factory=dict)


class AttackGraphSyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    nodes: list[GraphNodeInput] = Field(default_factory=list, max_length=5000)
    edges: list[GraphEdgeInput] = Field(default_factory=list, max_length=10000)


class AttackPathRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    start_node_key: str = Field(min_length=1, max_length=255)
    destination_node_key: str | None = Field(default=None, max_length=255)
    max_depth: int = Field(default=8, ge=1, le=12)
    only_high_value_destinations: bool = False


class AttackGraphSyncRunRead(ORMModel):
    id: uuid.UUID
    scenario: str
    status: str
    nodes_written: int
    edges_written: int
    source_summary: dict
    created_at: datetime


class AttackPathEvidenceRead(ORMModel):
    id: uuid.UUID
    path_id: uuid.UUID
    edge_index: int
    relationship_type: str
    source_node_key: str
    target_node_key: str
    evidence_status: str
    confidence: str
    source: str
    details: dict
    created_at: datetime


class AttackPathRecordRead(ORMModel):
    id: uuid.UUID
    sync_run_id: uuid.UUID
    scenario: str
    start_node_key: str
    destination_node_key: str
    path_length: int
    entry_point_exposure: str
    weakest_control: str | None
    critical_destination: bool
    enabling_findings: int
    credential_dependency: bool
    privilege_increase: bool
    reachable_high_value_asset: bool
    path_status: str
    confidence: str
    confidence_score: float
    evidence: list
    node_sequence: list
    relationship_sequence: list
    rationale: str
    created_at: datetime


class AttackPathResult(BaseModel):
    path: AttackPathRecordRead
    edge_evidence: list[AttackPathEvidenceRead]
