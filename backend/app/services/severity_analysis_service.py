from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.severity_analysis import VulnerabilitySeverityAnalysis
from app.services.cvss_engine import parse_cvss
from app.services.environmental_priority import calculate_environmental_priority


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def analyze_and_store(
    db: Session,
    *,
    canonical_id: str,
    vector: str,
    source: str,
    asset_criticality: int,
    exposure: int,
    exploit_maturity: int,
    kev: bool,
    epss: float | None,
) -> VulnerabilitySeverityAnalysis:
    parsed = parse_cvss(vector)
    priority = calculate_environmental_priority(
        cvss_base_score=parsed.base_score,
        asset_criticality=asset_criticality,
        exposure=exposure,
        exploit_maturity=exploit_maturity,
        kev=kev,
        epss=epss,
    )

    row = VulnerabilitySeverityAnalysis(
        canonical_id=canonical_id,
        original_vector=parsed.original_vector,
        source=source,
        score_version=parsed.version,
        base_score=parsed.base_score,
        severity=parsed.severity,
        parsed_components=parsed.components,
        environmental_priority=priority.score,
        priority_band=priority.band,
        priority_factors=priority.factors,
        rationale=priority.rationale,
        calculated_at=utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_analyses(db: Session, canonical_id: str | None = None):
    stmt = select(VulnerabilitySeverityAnalysis)
    if canonical_id:
        stmt = stmt.where(VulnerabilitySeverityAnalysis.canonical_id == canonical_id)
    return list(
        db.scalars(
            stmt.order_by(VulnerabilitySeverityAnalysis.calculated_at.desc())
        ).all()
    )
