from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.grounded_analyst import (
    GroundedAnalystRequest,
    GroundedAnalystResponse,
    GroundedAnalystRunRead,
)
from app.services.grounded_analyst_service import analyze_and_store, get_run, list_runs

router = APIRouter(
    prefix="/analyst",
    tags=["grounded-vulnforge-ai-analyst"],
)


@router.post(
    "/analyze",
    response_model=GroundedAnalystResponse,
    status_code=status.HTTP_201_CREATED,
)
def analyze(
    payload: GroundedAnalystRequest,
    db: Session = Depends(get_db),
):
    run, output = analyze_and_store(db, payload)
    return GroundedAnalystResponse(
        run=run,
        analysis=output,
    )


@router.get(
    "/runs",
    response_model=list[GroundedAnalystRunRead],
)
def runs(db: Session = Depends(get_db)):
    return list_runs(db)


@router.get(
    "/runs/{run_id}",
    response_model=GroundedAnalystRunRead,
)
def run_detail(
    run_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    row = get_run(db, run_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Grounded analyst run not found.",
        )
    return row
