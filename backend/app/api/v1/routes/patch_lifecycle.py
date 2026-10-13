from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.patch_lifecycle import (
    LifecycleFindingRead,
    PatchFindingRead,
    PatchLifecycleAssessmentRequest,
    PatchLifecycleAssessmentResult,
    PatchLifecycleRunRead,
)
from app.services.lifecycle_catalog import LIFECYCLE_CATALOG, lookup_lifecycle
from app.services.patch_lifecycle_service import (
    list_lifecycle_findings,
    list_patch_findings,
    list_runs,
    run_patch_lifecycle_assessment,
)

router = APIRouter(prefix="/patch-lifecycle", tags=["patch-lifecycle-risk"])


@router.get("/catalog")
def catalog():
    rows = []
    for (product, version), record in LIFECYCLE_CATALOG.items():
        rows.append(
            {
                "product": product,
                "version": version,
                **record,
            }
        )
    return rows


@router.get("/catalog/lookup")
def catalog_lookup(product: str, version: str):
    record = lookup_lifecycle(product, version)
    if record is None:
        raise HTTPException(status_code=404, detail="Lifecycle record not found.")
    return {
        "product": product,
        "version": version,
        **record,
    }


@router.post(
    "/assess",
    response_model=PatchLifecycleAssessmentResult,
    status_code=status.HTTP_201_CREATED,
)
def assess(
    payload: PatchLifecycleAssessmentRequest,
    db: Session = Depends(get_db),
):
    try:
        run, patch_findings, lifecycle_findings = run_patch_lifecycle_assessment(
            db,
            asset_id=payload.asset_id,
            source_name=payload.source_name,
            patch_observations=[item.model_dump() for item in payload.patch_observations],
            lifecycle_observations=[item.model_dump() for item in payload.lifecycle_observations],
        )
        return PatchLifecycleAssessmentResult(
            run=run,
            patch_findings=patch_findings,
            lifecycle_findings=lifecycle_findings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/runs", response_model=list[PatchLifecycleRunRead])
def runs(db: Session = Depends(get_db)):
    return list_runs(db)


@router.get("/runs/{run_id}/patch-findings", response_model=list[PatchFindingRead])
def patch_findings(run_id: uuid.UUID, db: Session = Depends(get_db)):
    return list_patch_findings(db, run_id)


@router.get("/runs/{run_id}/lifecycle-findings", response_model=list[LifecycleFindingRead])
def lifecycle_findings(run_id: uuid.UUID, db: Session = Depends(get_db)):
    return list_lifecycle_findings(db, run_id)
