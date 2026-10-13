from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class NormalizedIntelRecord:
    canonical_id: str
    cve_id: str | None = None
    osv_id: str | None = None
    cwes: list[str] = field(default_factory=list)
    cvss31_score: float | None = None
    cvss31_vector: str | None = None
    cvss4_score: float | None = None
    cvss4_vector: str | None = None
    cpes: list[dict[str, Any]] = field(default_factory=list)
    affected_ranges: list[dict[str, Any]] = field(default_factory=list)
    fixed_ranges: list[dict[str, Any]] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    kev: bool | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    vendor_advisories: list[dict[str, Any]] = field(default_factory=list)
    known_ransomware_use: bool | None = None
    required_action: str | None = None
    confidence: str = "high confidence"
    source_record_modified_at: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)
