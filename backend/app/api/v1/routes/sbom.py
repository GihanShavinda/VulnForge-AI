from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.sbom import (
    ComponentDriftEvent,
    PackageComponent,
    PackageVulnerabilityMatch,
    SbomImport,
    VulnerabilityAdvisory,
)
from app.schemas.sbom import (
    AdvisoryCreate,
    ComponentDriftRead,
    PackageComponentRead,
    PackageVulnerabilityMatchRead,
    SbomImportRead,
    SbomImportRequest,
    SbomImportResult,
    VulnerabilityAdvisoryRead,
)
from app.services.sbom_service import import_sbom

router = APIRouter(prefix="/sbom", tags=["sbom-package-assessment"])


@router.post("/imports", response_model=SbomImportResult, status_code=status.HTTP_201_CREATED)
def create_import(payload: SbomImportRequest, db: Session = Depends(get_db)):
    try:
        sbom, components, matches, drift = import_sbom(
            db,
            asset_id=payload.asset_id,
            fmt=payload.format,
            source_name=payload.source_name,
            document=payload.document,
            raw_text=payload.raw_text,
        )
        return SbomImportResult(
            sbom_import=sbom,
            components=components,
            matches=matches,
            drift=drift,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/imports", response_model=list[SbomImportRead])
def list_imports(
    asset_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    stmt = select(SbomImport)
    if asset_id:
        stmt = stmt.where(SbomImport.asset_id == asset_id)
    return db.scalars(stmt.order_by(SbomImport.imported_at.desc()).limit(limit)).all()


@router.get("/imports/{import_id}/components", response_model=list[PackageComponentRead])
def list_components(import_id: uuid.UUID, db: Session = Depends(get_db)):
    if db.get(SbomImport, import_id) is None:
        raise HTTPException(status_code=404, detail="SBOM import not found.")
    return db.scalars(
        select(PackageComponent)
        .where(PackageComponent.sbom_import_id == import_id)
        .order_by(PackageComponent.ecosystem, PackageComponent.name, PackageComponent.version)
    ).all()


@router.get("/imports/{import_id}/matches", response_model=list[PackageVulnerabilityMatchRead])
def list_matches(import_id: uuid.UUID, db: Session = Depends(get_db)):
    if db.get(SbomImport, import_id) is None:
        raise HTTPException(status_code=404, detail="SBOM import not found.")
    return db.scalars(
        select(PackageVulnerabilityMatch)
        .where(PackageVulnerabilityMatch.sbom_import_id == import_id)
        .order_by(PackageVulnerabilityMatch.vulnerability_id)
    ).all()


@router.get("/imports/{import_id}/drift", response_model=list[ComponentDriftRead])
def list_drift(import_id: uuid.UUID, db: Session = Depends(get_db)):
    if db.get(SbomImport, import_id) is None:
        raise HTTPException(status_code=404, detail="SBOM import not found.")
    return db.scalars(
        select(ComponentDriftEvent)
        .where(ComponentDriftEvent.current_import_id == import_id)
        .order_by(ComponentDriftEvent.change_type, ComponentDriftEvent.identity_key)
    ).all()


@router.post("/advisories", response_model=VulnerabilityAdvisoryRead, status_code=status.HTTP_201_CREATED)
def create_advisory(payload: AdvisoryCreate, db: Session = Depends(get_db)):
    row = VulnerabilityAdvisory(
        vulnerability_id=payload.vulnerability_id,
        source=payload.source,
        ecosystem=payload.ecosystem,
        package_name=payload.package_name,
        purl=payload.purl,
        cpe=payload.cpe,
        affected_range=payload.affected_range,
        fixed_version=payload.fixed_version,
        version_scheme=payload.version_scheme,
        confidence=payload.confidence,
        evidence_json=payload.evidence,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.get("/advisories", response_model=list[VulnerabilityAdvisoryRead])
def list_advisories(
    vulnerability_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    stmt = select(VulnerabilityAdvisory)
    if vulnerability_id:
        stmt = stmt.where(VulnerabilityAdvisory.vulnerability_id == vulnerability_id)
    return db.scalars(stmt.order_by(VulnerabilityAdvisory.created_at.desc()).limit(limit)).all()
