from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.weakness_context import BehaviourObservation, WeaknessTechniqueMapping
from app.schemas.weakness_context import (
    BehaviourObservationCreate,
    BehaviourObservationRead,
    FindingContextResponse,
    FindingTechniqueMappingCreate,
    FindingTechniqueMappingRead,
    VulnerabilityContextResponse,
)
from app.services.weakness_attack_catalog import get_attack_technique
from app.services.weakness_context_service import (
    build_finding_context,
    build_vulnerability_context,
    ensure_attack_catalog,
)

router = APIRouter(prefix="/weakness-context", tags=["weakness-adversary-context"])


@router.get("/vulnerabilities/{canonical_id}", response_model=VulnerabilityContextResponse)
def vulnerability_context(canonical_id: str, db: Session = Depends(get_db)):
    ensure_attack_catalog(db)
    return build_vulnerability_context(db, canonical_id)




@router.post(
    "/finding-technique-mappings",
    response_model=FindingTechniqueMappingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_finding_technique_mapping(payload: FindingTechniqueMappingCreate, db: Session = Depends(get_db)):
    ensure_attack_catalog(db)
    technique = get_attack_technique(payload.attack_id)
    if technique is None:
        raise HTTPException(status_code=422, detail=f"Unsupported ATT&CK technique: {payload.attack_id}")

    existing = db.scalar(
        select(WeaknessTechniqueMapping).where(
            WeaknessTechniqueMapping.subject_type == "finding",
            WeaknessTechniqueMapping.subject_id == payload.finding_id,
            WeaknessTechniqueMapping.attack_id == payload.attack_id.upper(),
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="Finding/technique mapping already exists.")

    row = WeaknessTechniqueMapping(
        subject_type="finding",
        subject_id=payload.finding_id,
        attack_id=payload.attack_id.upper(),
        context_type="potential",
        mapping_confidence=payload.mapping_confidence,
        mapping_source=payload.mapping_source,
        mapping_rationale=payload.mapping_rationale,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.post(
    "/behaviour-observations",
    response_model=BehaviourObservationRead,
    status_code=status.HTTP_201_CREATED,
)
def create_behaviour_observation(payload: BehaviourObservationCreate, db: Session = Depends(get_db)):
    ensure_attack_catalog(db)
    technique = get_attack_technique(payload.attack_id)
    if technique is None:
        raise HTTPException(status_code=422, detail=f"Unsupported ATT&CK technique: {payload.attack_id}")

    row = BehaviourObservation(
        finding_id=payload.finding_id,
        canonical_id=payload.canonical_id,
        attack_id=payload.attack_id.upper(),
        context_type=payload.context_type,
        mapping_confidence=payload.mapping_confidence,
        mapping_source=payload.mapping_source,
        mapping_rationale=payload.mapping_rationale,
        evidence_json=payload.evidence,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.get("/findings/{finding_id}", response_model=FindingContextResponse)
def finding_context(finding_id: str, db: Session = Depends(get_db)):
    ensure_attack_catalog(db)
    return build_finding_context(db, finding_id)


@router.get("/behaviour-observations", response_model=list[BehaviourObservationRead])
def list_behaviour_observations(db: Session = Depends(get_db)):
    return db.scalars(
        select(BehaviourObservation).order_by(BehaviourObservation.created_at.desc())
    ).all()
