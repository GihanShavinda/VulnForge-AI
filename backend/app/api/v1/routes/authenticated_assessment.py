from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.authenticated_assessment import AuthenticatedEvidence, AuthenticatedScan, CredentialUseAudit
from app.models.security_lab import CredentialProfile
from app.schemas.authenticated_assessment import (AuthenticatedComparison, AuthenticatedEvidenceRead, AuthenticatedScanRequest, AuthenticatedScanResult, CredentialCreate, CredentialRead, CredentialRotateSecret, CredentialUseAuditRead, ImportedAssessmentRequest)
from app.services.authenticated_assessment_service import execute_authenticated_scan, import_authenticated_evidence
from app.services.authenticated_comparison import build_comparison
from app.services.credential_crypto import encrypt_secret

router=APIRouter(prefix="/authenticated", tags=["authenticated-assessment"])

@router.get("/credentials", response_model=list[CredentialRead])
def list_credentials(db: Session=Depends(get_db)):
    return db.scalars(select(CredentialProfile).order_by(CredentialProfile.name)).all()

@router.post("/credentials", response_model=CredentialRead, status_code=status.HTTP_201_CREATED)
def create_credential(payload: CredentialCreate, db: Session=Depends(get_db)):
    profile_id=uuid.uuid4()
    row=CredentialProfile(id=profile_id, name=payload.name, username=payload.username, secret_reference=f"enc:v1:{profile_id}", protocol=payload.protocol, auth_method=payload.auth_method, port=payload.port, encrypted_secret=encrypt_secret(payload.secret), failed_attempts=0, max_failed_attempts=payload.max_failed_attempts, description=payload.description, enabled=True)
    db.add(row); db.commit(); db.refresh(row); return row

@router.put("/credentials/{credential_id}/secret", response_model=CredentialRead)
def rotate_secret(credential_id: uuid.UUID, payload: CredentialRotateSecret, db: Session=Depends(get_db)):
    row=db.get(CredentialProfile, credential_id)
    if row is None: raise HTTPException(status_code=404, detail="Credential profile not found.")
    row.encrypted_secret=encrypt_secret(payload.secret); row.failed_attempts=0; row.lockout_until=None
    db.commit(); db.refresh(row); return row

@router.post("/scans", response_model=AuthenticatedScanResult, status_code=status.HTTP_201_CREATED)
def run_scan(payload: AuthenticatedScanRequest, db: Session=Depends(get_db)):
    try:
        scan,evidence=execute_authenticated_scan(db, asset_id=payload.asset_id, credential_profile_id=payload.credential_profile_id, explicitly_authorized=payload.explicitly_authorized)
        return AuthenticatedScanResult(scan=scan,evidence=evidence)
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc
    except RuntimeError as exc: raise HTTPException(status_code=502,detail=str(exc)) from exc

@router.post("/scans/import", response_model=AuthenticatedScanResult, status_code=status.HTTP_201_CREATED)
def import_scan(payload: ImportedAssessmentRequest, db: Session=Depends(get_db)):
    try:
        scan,evidence=import_authenticated_evidence(db, asset_id=payload.asset_id, source_name=payload.source_name, explicitly_authorized=payload.explicitly_authorized, evidence_items=payload.evidence)
        return AuthenticatedScanResult(scan=scan,evidence=evidence)
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc

@router.get("/scans/{scan_id}/evidence", response_model=list[AuthenticatedEvidenceRead])
def get_evidence(scan_id: uuid.UUID, db: Session=Depends(get_db)):
    if db.get(AuthenticatedScan,scan_id) is None: raise HTTPException(status_code=404,detail="Authenticated scan not found.")
    return db.scalars(select(AuthenticatedEvidence).where(AuthenticatedEvidence.authenticated_scan_id==scan_id).order_by(AuthenticatedEvidence.category)).all()

@router.get("/scans/{scan_id}/comparison", response_model=AuthenticatedComparison)
def comparison(scan_id: uuid.UUID, db: Session=Depends(get_db)):
    scan=db.get(AuthenticatedScan,scan_id)
    if scan is None: raise HTTPException(status_code=404,detail="Authenticated scan not found.")
    return AuthenticatedComparison(scan_id=scan.id, rows=build_comparison(db,scan))

@router.get("/credential-audits", response_model=list[CredentialUseAuditRead])
def list_credential_audits(limit:int=Query(default=200,ge=1,le=1000), db: Session=Depends(get_db)):
    return db.scalars(select(CredentialUseAudit).order_by(CredentialUseAudit.created_at.desc()).limit(limit)).all()
