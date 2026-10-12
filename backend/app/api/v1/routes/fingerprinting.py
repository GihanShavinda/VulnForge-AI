from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.fingerprinting import FingerprintEvidence, FingerprintJob, Technology, TechnologyObservation
from app.models.security_lab import Asset
from app.schemas.fingerprinting import FingerprintEvidenceRead, FingerprintJobRead, FingerprintRequest, FingerprintResult, TechnologyObservationRead, TechnologyRead
from app.services.audit_service import write_audit_log
from app.services.fingerprinting_service import execute_fingerprinting

router = APIRouter(tags=["fingerprinting"])


@router.post("/fingerprints", response_model=FingerprintResult, status_code=status.HTTP_201_CREATED)
def run_fingerprint(payload: FingerprintRequest, db: Session = Depends(get_db)):
    asset = db.get(Asset, payload.asset_id)
    target_for_audit = asset.ip_address if asset else str(payload.asset_id)
    try:
        job, observations, evidence = execute_fingerprinting(
            db,
            asset_id=payload.asset_id,
            explicitly_authorized=payload.explicitly_authorized,
            run_nmap_os=payload.run_nmap_os,
            run_whatweb_enabled=payload.run_whatweb,
            collect_http_headers=payload.collect_http_headers,
            authenticated_inventory=payload.authenticated_inventory,
        )
    except PermissionError as exc:
        write_audit_log(db, event_type="fingerprinting_scope_denied", target=target_for_audit, allowed=False, reason=str(exc), details={"asset_id": str(payload.asset_id)})
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    write_audit_log(db, event_type="fingerprinting_completed", target=job.target, allowed=True, reason=f"Fingerprinting finished with status '{job.status}'.", details={"job_id": str(job.id), "asset_id": str(payload.asset_id), "technology_observations": len(observations), "evidence_records": len(evidence)})
    return FingerprintResult(job=job, observations=observations, evidence_count=len(evidence))


@router.get("/assets/{asset_id}/technologies", response_model=list[TechnologyObservationRead])
def list_asset_technologies(asset_id: uuid.UUID, preferred_only: bool = Query(default=False), limit: int = Query(default=500, ge=1, le=2000), db: Session = Depends(get_db)):
    query = select(TechnologyObservation).where(TechnologyObservation.asset_id == asset_id)
    if preferred_only:
        query = query.where(TechnologyObservation.is_preferred.is_(True))
    query = query.order_by(TechnologyObservation.last_seen.desc()).limit(limit)
    return db.scalars(query).all()


@router.get("/fingerprints/{job_id}", response_model=FingerprintJobRead)
def get_fingerprint_job(job_id: uuid.UUID, db: Session = Depends(get_db)):
    job = db.get(FingerprintJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Fingerprint job not found.")
    return job


@router.get("/fingerprints/{job_id}/evidence", response_model=list[FingerprintEvidenceRead])
def get_fingerprint_evidence(job_id: uuid.UUID, db: Session = Depends(get_db)):
    job = db.get(FingerprintJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Fingerprint job not found.")
    return db.scalars(select(FingerprintEvidence).where(FingerprintEvidence.fingerprint_job_id == job.id).order_by(FingerprintEvidence.captured_at, FingerprintEvidence.source_type)).all()


@router.get("/technologies", response_model=list[TechnologyRead])
def list_technology_catalog(category: str | None = None, limit: int = Query(default=500, ge=1, le=2000), db: Session = Depends(get_db)):
    query = select(Technology)
    if category:
        query = query.where(Technology.category == category)
    return db.scalars(query.order_by(Technology.category, Technology.name).limit(limit)).all()
