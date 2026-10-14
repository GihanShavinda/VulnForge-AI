from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.security_control_awareness import (
    SecurityControlCreate, SecurityControlRead,
    ControlRiskAssessmentRequest, ControlRiskAssessmentRead,
    ControlRiskContributionRead, ControlRiskAssessmentResult,
)
from app.services.security_control_service import (
    create_control, list_controls, calculate_and_store_assessment,
    list_assessments, get_assessment, list_contributions,
)

router = APIRouter(prefix="/security-controls", tags=["security-control-awareness"])

@router.post("", response_model=SecurityControlRead, status_code=status.HTTP_201_CREATED)
def create(payload: SecurityControlCreate, db: Session = Depends(get_db)):
    try:
        return create_control(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@router.get("", response_model=list[SecurityControlRead])
def controls(asset_id: uuid.UUID | None = Query(default=None), db: Session = Depends(get_db)):
    return list_controls(db, asset_id)

@router.post("/assess", response_model=ControlRiskAssessmentResult, status_code=status.HTTP_201_CREATED)
def assess(payload: ControlRiskAssessmentRequest, db: Session = Depends(get_db)):
    try:
        assessment, contributions = calculate_and_store_assessment(db, payload)
        return ControlRiskAssessmentResult(assessment=assessment, contributions=contributions)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@router.get("/assessments", response_model=list[ControlRiskAssessmentRead])
def assessments(db: Session = Depends(get_db)):
    return list_assessments(db)

@router.get("/assessments/{assessment_id}", response_model=ControlRiskAssessmentRead)
def assessment_detail(assessment_id: uuid.UUID, db: Session = Depends(get_db)):
    row = get_assessment(db, assessment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Control risk assessment not found.")
    return row

@router.get("/assessments/{assessment_id}/contributions", response_model=list[ControlRiskContributionRead])
def assessment_contributions(assessment_id: uuid.UUID, db: Session = Depends(get_db)):
    if get_assessment(db, assessment_id) is None:
        raise HTTPException(status_code=404, detail="Control risk assessment not found.")
    return list_contributions(db, assessment_id)
