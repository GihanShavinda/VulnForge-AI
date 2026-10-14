from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ReportType = Literal[
    "executive",
    "technical_vulnerability_assessment",
    "asset",
    "attack_path",
    "remediation",
    "verification",
]

ReportFormat = Literal["pdf", "csv", "json"]


class ReportSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    heading: str
    rows: list[dict] = Field(default_factory=list)
    narrative: str | None = None


class FinalReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: ReportType
    report_format: ReportFormat
    title: str
    generated_for: str = "VulnForge VMware Laboratory"
    sections: list[ReportSection] = Field(min_length=1)
