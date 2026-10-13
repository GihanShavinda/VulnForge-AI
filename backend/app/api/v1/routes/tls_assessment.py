from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.tls_assessment import (
    TLSAssessmentRequest,TLSAssessmentResult,TLSAssessmentImportRead,
    TLSEvidenceRead,CryptoFindingRead,TLSScannerParseRequest,
)
from app.services.tls_assessment_service import run_tls_assessment,list_imports,list_findings,list_evidence
from app.services.tls_scanner_parsers import parse_tls_scanner

router=APIRouter(prefix="/tls-assessment",tags=["tls-security-assessment"])

@router.post("/parse")
def parse_scanner(payload: TLSScannerParseRequest):
    try:
        return {"evidence":parse_tls_scanner(payload.scanner,payload.payload)}
    except (ValueError,TypeError) as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc

@router.post("/assess",response_model=TLSAssessmentResult,status_code=status.HTTP_201_CREATED)
def assess(payload: TLSAssessmentRequest,db: Session=Depends(get_db)):
    try:
        run,findings=run_tls_assessment(
            db,asset_id=payload.asset_id,target=payload.target,port=payload.port,
            scanner=payload.scanner,source_name=payload.source_name,lab_context=payload.lab_context,
            evidence_items=[{
                "category":x.category,"observed_value":x.observed_value,
                "source_locator":x.source_locator,"confidence":x.confidence,"raw":x.raw
            } for x in payload.evidence],
        )
        return TLSAssessmentResult(run=run,findings=findings)
    except ValueError as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc

@router.get("/imports",response_model=list[TLSAssessmentImportRead])
def imports(db: Session=Depends(get_db)):
    return list_imports(db)

@router.get("/imports/{import_id}/findings",response_model=list[CryptoFindingRead])
def findings(import_id: uuid.UUID,db: Session=Depends(get_db)):
    return list_findings(db,import_id)

@router.get("/imports/{import_id}/evidence",response_model=list[TLSEvidenceRead])
def evidence(import_id: uuid.UUID,db: Session=Depends(get_db)):
    return list_evidence(db,import_id)
