from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.evaluation import EvaluationRun
from app.models.remediation import ReassessmentRun, RemediationCase


DASHBOARD_SECTIONS = [
    "Exposure Overview",
    "Asset Risk",
    "Vulnerability Intelligence",
    "Attack Surface",
    "Attack Paths",
    "Configuration Weaknesses",
    "Web Security",
    "TLS Security",
    "Secrets",
    "Patch / EOL",
    "Remediation",
    "Verification",
    "Risk Trends",
]


def final_dashboard(db: Session) -> dict:
    remediation_total = db.scalar(select(func.count()).select_from(RemediationCase)) or 0
    open_cases = db.scalar(
        select(func.count()).select_from(RemediationCase).where(
            RemediationCase.status.notin_(["Closed", "False Positive"])
        )
    ) or 0
    verified_cases = db.scalar(
        select(func.count()).select_from(RemediationCase).where(
            RemediationCase.status.in_(["Verified", "Closed"])
        )
    ) or 0
    reassessments = db.scalar(select(func.count()).select_from(ReassessmentRun)) or 0
    regressions = db.scalar(
        select(func.count()).select_from(ReassessmentRun).where(
            ReassessmentRun.regression_detected.is_(True)
        )
    ) or 0
    evaluations = db.scalar(select(func.count()).select_from(EvaluationRun)) or 0

    sections = [
        {
            "name": name,
            "status": "available",
            "description": (
                "Final VulnForge dashboard section. Data is sourced from the corresponding "
                "V1-V20 API and persisted evidence stores."
            ),
        }
        for name in DASHBOARD_SECTIONS
    ]

    return {
        "milestone": "V20",
        "sections": sections,
        "remediation_summary": {
            "total_cases": remediation_total,
            "open_cases": open_cases,
            "verified_or_closed": verified_cases,
            "reassessments": reassessments,
            "regressions_detected": regressions,
        },
        "evaluation_summary": {
            "evaluation_runs": evaluations,
            "environment": "VMware VulnForge Laboratory",
        },
    }
