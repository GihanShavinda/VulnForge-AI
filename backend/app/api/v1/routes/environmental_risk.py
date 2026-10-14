from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.environmental_risk import (
    EnvironmentalRiskContributionRead,
    EnvironmentalRiskScoreRead,
    EnvironmentalRiskScoreRequest,
    EnvironmentalRiskScoreResult,
    RiskScoreVersionCreate,
    RiskScoreVersionRead,
)
from app.services.environmental_risk_service import (
    calculate_and_store,
    create_score_version,
    get_score,
    list_contributions,
    list_score_versions,
    list_scores,
)

router = APIRouter(
    prefix="/environmental-risk",
    tags=["environmental-risk-score-2"],
)


@router.post(
    "/versions",
    response_model=RiskScoreVersionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_version(
    payload: RiskScoreVersionCreate,
    db: Session = Depends(get_db),
):
    try:
        return create_score_version(
            db,
            version_key=payload.version_key,
            name=payload.name,
            description=payload.description,
            experimental=payload.experimental,
            active=payload.active,
            weights=payload.weights,
            interaction_rules=payload.interaction_rules,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/versions",
    response_model=list[RiskScoreVersionRead],
)
def versions(db: Session = Depends(get_db)):
    return list_score_versions(db)


@router.post(
    "/score",
    response_model=EnvironmentalRiskScoreResult,
    status_code=status.HTTP_201_CREATED,
)
def score(
    payload: EnvironmentalRiskScoreRequest,
    db: Session = Depends(get_db),
):
    try:
        risk_score, contributions = calculate_and_store(
            db,
            asset_id=payload.asset_id,
            vulnerability_id=payload.vulnerability_id,
            calculation_version=payload.calculation_version,
            factors=payload.factors.model_dump(),
        )
        return EnvironmentalRiskScoreResult(
            score=risk_score,
            contributions=contributions,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/scores",
    response_model=list[EnvironmentalRiskScoreRead],
)
def scores(db: Session = Depends(get_db)):
    return list_scores(db)


@router.get(
    "/scores/{score_id}",
    response_model=EnvironmentalRiskScoreRead,
)
def score_detail(
    score_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    row = get_score(db, score_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Risk score not found.")
    return row


@router.get(
    "/scores/{score_id}/contributions",
    response_model=list[EnvironmentalRiskContributionRead],
)
def contributions(
    score_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    if get_score(db, score_id) is None:
        raise HTTPException(status_code=404, detail="Risk score not found.")
    return list_contributions(db, score_id)
