from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.enumeration import EnumerationEvidence, EnumerationJob, ExposureFinding, ServiceObservation
from app.models.security_lab import Asset
from app.schemas.enumeration import (
    EnumerationEvidenceRead,
    ExposureFindingRead,
    ServiceEnumerationRequest,
    ServiceEnumerationResult,
    ServiceObservationRead,
)
from app.services.audit_service import write_audit_log
from app.services.enumeration_service import execute_service_enumeration

router = APIRouter(tags=["service-enumeration"])


@router.post(
    "/scans/services",
    response_model=ServiceEnumerationResult,
    status_code=status.HTTP_201_CREATED,
)
def run_service_enumeration(payload: ServiceEnumerationRequest, db: Session = Depends(get_db)):
    asset = db.get(Asset, payload.asset_id)
    target_for_audit = asset.ip_address if asset else str(payload.asset_id)

    try:
        job, services, findings = execute_service_enumeration(
            db,
            asset_id=payload.asset_id,
            protocol=payload.protocol,
            top_ports=payload.top_ports,
            explicitly_authorized=payload.explicitly_authorized,
        )
    except PermissionError as exc:
        write_audit_log(
            db,
            event_type="service_enumeration_scope_denied",
            target=target_for_audit,
            allowed=False,
            reason=str(exc),
            details={"protocol": payload.protocol, "asset_id": str(payload.asset_id)},
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    write_audit_log(
        db,
        event_type="service_enumeration_completed",
        target=job.target,
        allowed=True,
        reason=f"Nmap {payload.protocol.upper()} service enumeration completed.",
        details={
            "job_id": str(job.id),
            "asset_id": str(payload.asset_id),
            "services": len(services),
            "exposure_findings": len(findings),
        },
    )
    return ServiceEnumerationResult(job=job, services=services, findings=findings)


@router.get("/assets/{asset_id}/services", response_model=list[ServiceObservationRead])
def list_asset_services(
    asset_id: uuid.UUID,
    open_only: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    query = select(ServiceObservation).where(ServiceObservation.asset_id == asset_id)
    if open_only:
        query = query.where(ServiceObservation.state == "open")
    query = query.order_by(ServiceObservation.last_seen.desc(), ServiceObservation.protocol, ServiceObservation.port)
    return db.scalars(query).all()


@router.get("/exposures", response_model=list[ExposureFindingRead])
def list_exposure_findings(
    asset_id: uuid.UUID | None = None,
    severity: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    query = select(ExposureFinding)
    if asset_id is not None:
        query = query.where(ExposureFinding.asset_id == asset_id)
    if severity:
        query = query.where(ExposureFinding.severity == severity.lower())
    query = query.order_by(ExposureFinding.created_at.desc()).limit(limit)
    return db.scalars(query).all()


@router.get("/scans/services/{scan_id}/evidence", response_model=EnumerationEvidenceRead)
def get_service_evidence(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    job = db.get(EnumerationJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Service enumeration scan not found.")

    evidence = db.scalar(
        select(EnumerationEvidence).where(EnumerationEvidence.enumeration_job_id == job.id)
    )
    if evidence is None:
        raise HTTPException(status_code=404, detail="Service enumeration evidence not found.")
    return evidence
