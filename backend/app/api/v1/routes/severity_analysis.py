from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.severity_analysis import (
    SeverityAnalyzeRequest,
    SeverityAnalysisRead,
    SeverityComparisonResponse,
    SeverityComparisonRow,
)
from app.services.severity_analysis_service import analyze_and_store, list_analyses

router = APIRouter(prefix="/severity", tags=["vulnerability-severity"])


@router.post("/analyze", response_model=SeverityAnalysisRead, status_code=status.HTTP_201_CREATED)
def analyze(payload: SeverityAnalyzeRequest, db: Session = Depends(get_db)):
    try:
        ctx = payload.environmental_context
        return analyze_and_store(
            db,
            canonical_id=payload.canonical_id,
            vector=payload.vector,
            source=payload.source,
            asset_criticality=ctx.asset_criticality,
            exposure=ctx.exposure,
            exploit_maturity=ctx.exploit_maturity,
            kev=ctx.kev,
            epss=ctx.epss,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/analyses", response_model=list[SeverityAnalysisRead])
def analyses(canonical_id: str | None = None, db: Session = Depends(get_db)):
    return list_analyses(db, canonical_id)


@router.get("/compare/{canonical_id}", response_model=SeverityComparisonResponse)
def compare(canonical_id: str, db: Session = Depends(get_db)):
    rows = list_analyses(db, canonical_id)
    return SeverityComparisonResponse(
        rows=[
            SeverityComparisonRow(
                canonical_id=row.canonical_id,
                cvss_version=row.score_version,
                cvss_score=row.base_score,
                cvss_severity=row.severity,
                environmental_priority=row.environmental_priority,
                environmental_priority_band=row.priority_band,
                source=row.source,
                rationale=row.rationale,
            )
            for row in rows
        ],
        note=(
            "CVSS severity and VulnForge environmental priority are separate. "
            "CVSS alone is never used as the VulnForge priority."
        ),
    )
