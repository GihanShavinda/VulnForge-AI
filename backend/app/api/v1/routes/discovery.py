from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.discovery import (
    DiscoveryEvidence,
    DiscoveryJob,
    DiscoveredHost,
)
from app.schemas.discovery import (
    DiscoveryEvidenceRead,
    DiscoveryJobResult,
    DiscoveryRequest,
    DiscoveredHostRead,
)
from app.services.audit_service import write_audit_log
from app.services.discovery_service import execute_discovery


router = APIRouter(tags=["discovery"])


@router.post(
    "/scans/discovery",
    response_model=DiscoveryJobResult,
    status_code=status.HTTP_201_CREATED,
)
def run_discovery(
    payload: DiscoveryRequest,
    db: Session = Depends(get_db),
):
    """
    Start an authorized Nmap host-discovery scan.

    Supported methods:
    - arp
    - icmp
    - tcp

    The discovery service performs ScanScope validation before
    Nmap is allowed to execute.
    """
    try:
        job, hosts = execute_discovery(
            db,
            target=payload.target,
            method=payload.method,
            explicitly_authorized=payload.explicitly_authorized,
        )

    except PermissionError as exc:
        write_audit_log(
            db,
            event_type="discovery_scope_denied",
            target=payload.target,
            allowed=False,
            reason=str(exc),
            details={
                "method": payload.method,
            },
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    write_audit_log(
        db,
        event_type="discovery_completed",
        target=payload.target,
        allowed=True,
        reason=f"Nmap {payload.method} discovery completed.",
        details={
            "job_id": str(job.id),
            "method": payload.method,
            "observations": len(hosts),
        },
    )

    return DiscoveryJobResult(
        job=job,
        hosts=hosts,
    )


@router.get(
    "/assets/discovered",
    response_model=list[DiscoveredHostRead],
)
def list_discovered_hosts(
    db: Session = Depends(get_db),
):
    """
    Return discovered-host observations ordered newest first.
    """
    return db.scalars(
        select(DiscoveredHost).order_by(
            DiscoveredHost.scan_timestamp.desc(),
            DiscoveredHost.ip_address,
        )
    ).all()


@router.get(
    "/scans/{scan_id}/evidence",
    response_model=DiscoveryEvidenceRead,
)
def get_discovery_evidence(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """
    Return the preserved raw Nmap XML evidence for a discovery job.
    """
    try:
        job_id = uuid.UUID(scan_id)

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid discovery scan ID.",
        ) from exc

    job = db.get(
        DiscoveryJob,
        job_id,
    )

    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Discovery scan not found.",
        )

    evidence = db.scalar(
        select(DiscoveryEvidence).where(
            DiscoveryEvidence.discovery_job_id == job.id
        )
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Discovery evidence not found.",
        )

    return evidence