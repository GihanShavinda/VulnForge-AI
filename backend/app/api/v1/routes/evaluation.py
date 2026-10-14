from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.evaluation import EvaluationRunCreate, EvaluationRunRead
from app.services.evaluation_service import (
    create_evaluation,
    get_evaluation,
    list_evaluations,
)

router = APIRouter(
    prefix="/evaluation",
    tags=["final-evaluation"],
)


@router.post(
    "/runs",
    response_model=EvaluationRunRead,
    status_code=status.HTTP_201_CREATED,
)
def create(
    payload: EvaluationRunCreate,
    db: Session = Depends(get_db),
):
    return create_evaluation(db, payload)


@router.get(
    "/runs",
    response_model=list[EvaluationRunRead],
)
def runs(db: Session = Depends(get_db)):
    return list_evaluations(db)


@router.get(
    "/runs/{run_id}",
    response_model=EvaluationRunRead,
)
def run_detail(
    run_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    row = get_evaluation(db, run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Evaluation run not found.")
    return row
