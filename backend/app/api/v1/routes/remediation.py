from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.remediation import (
    ReassessmentRead,
    ReassessmentRequest,
    RemediationCaseCreate,
    RemediationCaseDetail,
    RemediationCaseRead,
    RemediationEvidenceCreate,
    RemediationEvidenceRead,
    StatusTransitionRequest,
)
from app.services.remediation_service import (
    add_evidence,
    create_case,
    get_case,
    list_cases,
    list_evidence,
    list_reassessments,
    run_reassessment,
    transition_case,
)

router = APIRouter(
    prefix="/remediation",
    tags=["remediation-engineering"],
)


@router.post(
    "/cases",
    response_model=RemediationCaseRead,
    status_code=status.HTTP_201_CREATED,
)
def create(
    payload: RemediationCaseCreate,
    db: Session = Depends(get_db),
):
    return create_case(db, payload)


@router.get(
    "/cases",
    response_model=list[RemediationCaseRead],
)
def cases(db: Session = Depends(get_db)):
    return list_cases(db)


@router.get(
    "/cases/{case_id}",
    response_model=RemediationCaseDetail,
)
def case_detail(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    row = get_case(db, case_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Remediation case not found.")

    return RemediationCaseDetail(
        case=row,
        evidence=list_evidence(db, case_id),
        reassessments=list_reassessments(db, case_id),
    )


@router.post(
    "/cases/{case_id}/evidence",
    response_model=RemediationEvidenceRead,
    status_code=status.HTTP_201_CREATED,
)
def evidence(
    case_id: uuid.UUID,
    payload: RemediationEvidenceCreate,
    db: Session = Depends(get_db),
):
    try:
        return add_evidence(db, case_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/cases/{case_id}/reassess",
    response_model=ReassessmentRead,
    status_code=status.HTTP_201_CREATED,
)
def reassess(
    case_id: uuid.UUID,
    payload: ReassessmentRequest,
    db: Session = Depends(get_db),
):
    try:
        return run_reassessment(db, case_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/cases/{case_id}/transition",
    response_model=RemediationCaseRead,
)
def transition(
    case_id: uuid.UUID,
    payload: StatusTransitionRequest,
    db: Session = Depends(get_db),
):
    try:
        return transition_case(db, case_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
