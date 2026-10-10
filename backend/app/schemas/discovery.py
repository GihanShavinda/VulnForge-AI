from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class DiscoveryRequest(BaseModel):
    """
    Request payload for an authorized Nmap discovery scan.

    Preferred API field:
        method

    Backward compatibility:
        discovery_method

    Examples:
        {
            "target": "192.168.37.0/24",
            "method": "arp",
            "explicitly_authorized": true
        }
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    target: str = Field(
        min_length=1,
        max_length=128,
        examples=["192.168.37.0/24"],
    )

    method: Literal["icmp", "arp", "tcp"] = Field(
        default="icmp",
        description="Nmap host-discovery method.",
        examples=["arp"],
    )

    explicitly_authorized: bool = Field(
        default=False,
        description="Must be true when the ScanScope requires explicit authorization.",
    )

    @model_validator(mode="before")
    @classmethod
    def support_legacy_discovery_method(
        cls,
        data: Any,
    ) -> Any:
        """
        Accept the older 'discovery_method' request field while making
        'method' the canonical API field.

        If both are supplied they must contain the same value.
        """
        if not isinstance(data, dict):
            return data

        values = dict(data)

        legacy_method = values.get("discovery_method")
        current_method = values.get("method")

        if current_method is not None and legacy_method is not None:
            if current_method != legacy_method:
                raise ValueError(
                    "'method' and 'discovery_method' cannot contain "
                    "different values."
                )

        if current_method is None and legacy_method is not None:
            values["method"] = legacy_method

        # Remove the legacy field because extra fields are forbidden.
        values.pop("discovery_method", None)

        return values


class DiscoveryJobRead(ORMModel):
    id: uuid.UUID
    target: str
    discovery_method: str
    scan_source: str
    status: str
    explicitly_authorized: bool
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime


class DiscoveredHostRead(ORMModel):
    id: uuid.UUID
    discovery_job_id: uuid.UUID
    matched_asset_id: uuid.UUID | None
    ip_address: str
    hostname: str | None
    mac_address: str | None
    vendor: str | None
    reachable: bool
    state: str
    first_seen: datetime
    last_seen: datetime
    scan_source: str
    scan_timestamp: datetime
    identity_basis: str | None
    change_types: str | None


class DiscoveryEvidenceRead(ORMModel):
    id: uuid.UUID
    discovery_job_id: uuid.UUID
    evidence_type: str
    content_sha256: str
    raw_xml: str
    captured_at: datetime


class DiscoveryJobResult(BaseModel):
    job: DiscoveryJobRead
    hosts: list[DiscoveredHostRead]