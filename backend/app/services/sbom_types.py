from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class NormalizedComponent:
    name: str
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    cpe: str | None = None
    supplier: str | None = None
    package_origin: str | None = None
    source: str = "unknown"
    vendor_status: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    source_ref: str | None = None


@dataclass(frozen=True)
class DirectVulnerabilityFinding:
    vulnerability_id: str
    source: str
    component_ref: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    cpe: str | None = None
    fixed_version: str | None = None
    affected_range: str | None = None
    confidence: str = "high confidence"
    evidence: dict[str, Any] = field(default_factory=dict)
