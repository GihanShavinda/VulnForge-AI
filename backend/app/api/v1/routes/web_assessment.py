from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.web_assessment import (
    WebAssessmentImportRead,
    WebEvidenceRead,
    WebFindingRead,
    WebImportRequest,
    WebImportResult,
)
from app.services.web_assessment_service import (
    import_web_assessment,
    list_evidence,
    list_findings,
    list_imports,
)

router = APIRouter(prefix="/web-assessment", tags=["web-application-assessment"])


@router.post("/imports", response_model=WebImportResult, status_code=status.HTTP_201_CREATED)
def create_import(payload: WebImportRequest, db: Session = Depends(get_db)):
    try:
        run, findings, duplicates = import_web_assessment(
            db,
            asset_id=payload.asset_id,
            target_url=payload.target_url,
            scanner=payload.scanner,
            source_name=payload.source_name,
            payload=payload.payload,
        )
        return WebImportResult(
            run=run,
            findings=findings,
            duplicates_skipped=duplicates,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/imports", response_model=list[WebAssessmentImportRead])
def imports(db: Session = Depends(get_db)):
    return list_imports(db)


@router.get("/imports/{import_id}/findings", response_model=list[WebFindingRead])
def findings(import_id: uuid.UUID, db: Session = Depends(get_db)):
    return list_findings(db, import_id)


@router.get("/imports/{import_id}/evidence", response_model=list[WebEvidenceRead])
def evidence(import_id: uuid.UUID, db: Session = Depends(get_db)):
    return list_evidence(db, import_id)
