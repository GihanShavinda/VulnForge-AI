import ipaddress

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.security_lab import (
    Asset,
    AssetTag,
    AuditLog,
    CredentialProfile,
    Network,
    ScanProfile,
    ScanScope,
)
from app.schemas.security_lab import (
    AssetCreate,
    AssetRead,
    AssetTagCreate,
    AssetTagRead,
    AuditLogRead,
    CredentialProfileCreate,
    CredentialProfileRead,
    NetworkCreate,
    NetworkRead,
    ScanProfileCreate,
    ScanProfileRead,
    ScanScopeCreate,
    ScanScopeRead,
    ScopeValidationRequest,
    ScopeValidationResponse,
)
from app.services.audit_service import write_audit_log
from app.services.scope_validator import validate_target

router = APIRouter(prefix="/security-lab", tags=["security-lab"])


def _commit_or_409(db: Session, entity):
    try:
        db.add(entity)
        db.commit()
        db.refresh(entity)
        return entity
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A record with the same unique value already exists.",
        ) from exc


@router.get("/networks", response_model=list[NetworkRead])
def list_networks(db: Session = Depends(get_db)):
    return db.scalars(select(Network).order_by(Network.name)).all()


@router.post("/networks", response_model=NetworkRead, status_code=status.HTTP_201_CREATED)
def create_network(payload: NetworkCreate, db: Session = Depends(get_db)):
    return _commit_or_409(db, Network(**payload.model_dump()))


@router.get("/assets", response_model=list[AssetRead])
def list_assets(db: Session = Depends(get_db)):
    return db.scalars(select(Asset).order_by(Asset.hostname)).all()


@router.post("/assets", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    network = db.get(Network, payload.network_id)
    if network is None:
        raise HTTPException(status_code=404, detail="Network not found.")

    if ipaddress.ip_address(payload.ip_address) not in ipaddress.ip_network(network.cidr, strict=False):
        raise HTTPException(status_code=422, detail="Asset IP must belong to the selected network CIDR.")

    return _commit_or_409(db, Asset(**payload.model_dump()))


@router.get("/scopes", response_model=list[ScanScopeRead])
def list_scopes(db: Session = Depends(get_db)):
    return db.scalars(select(ScanScope).order_by(ScanScope.name)).all()


@router.post("/scopes", response_model=ScanScopeRead, status_code=status.HTTP_201_CREATED)
def create_scope(payload: ScanScopeCreate, db: Session = Depends(get_db)):
    network = db.get(Network, payload.network_id)
    if network is None:
        raise HTTPException(status_code=404, detail="Network not found.")

    scope_net = ipaddress.ip_network(payload.cidr, strict=False)
    parent_net = ipaddress.ip_network(network.cidr, strict=False)
    if not scope_net.subnet_of(parent_net):
        raise HTTPException(status_code=422, detail="Scan scope CIDR must be inside the selected network CIDR.")

    return _commit_or_409(db, ScanScope(**payload.model_dump()))


@router.get("/asset-tags", response_model=list[AssetTagRead])
def list_asset_tags(db: Session = Depends(get_db)):
    return db.scalars(select(AssetTag).order_by(AssetTag.name)).all()


@router.post("/asset-tags", response_model=AssetTagRead, status_code=status.HTTP_201_CREATED)
def create_asset_tag(payload: AssetTagCreate, db: Session = Depends(get_db)):
    return _commit_or_409(db, AssetTag(**payload.model_dump()))


@router.get("/credential-profiles", response_model=list[CredentialProfileRead])
def list_credential_profiles(db: Session = Depends(get_db)):
    return db.scalars(select(CredentialProfile).order_by(CredentialProfile.name)).all()


@router.post("/credential-profiles", response_model=CredentialProfileRead, status_code=status.HTTP_201_CREATED)
def create_credential_profile(payload: CredentialProfileCreate, db: Session = Depends(get_db)):
    return _commit_or_409(db, CredentialProfile(**payload.model_dump()))


@router.get("/scan-profiles", response_model=list[ScanProfileRead])
def list_scan_profiles(db: Session = Depends(get_db)):
    return db.scalars(select(ScanProfile).order_by(ScanProfile.name)).all()


@router.post("/scan-profiles", response_model=ScanProfileRead, status_code=status.HTTP_201_CREATED)
def create_scan_profile(payload: ScanProfileCreate, db: Session = Depends(get_db)):
    return _commit_or_409(db, ScanProfile(**payload.model_dump()))


@router.get("/audit-logs", response_model=list[AuditLogRead])
def list_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    safe_limit = max(1, min(limit, 500))
    return db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(safe_limit)).all()


@router.post("/validate-target", response_model=ScopeValidationResponse)
def validate_scan_target(payload: ScopeValidationRequest, db: Session = Depends(get_db)):
    scopes = db.scalars(
        select(ScanScope)
        .join(Network, ScanScope.network_id == Network.id)
        .where(ScanScope.enabled.is_(True), Network.approved_for_scanning.is_(True))
    ).all()

    decision = validate_target(
        payload.target,
        list(scopes),
        explicitly_authorized=payload.explicitly_authorized,
    )

    write_audit_log(
        db,
        event_type="scope_validation",
        target=payload.target,
        allowed=decision.allowed,
        reason=decision.reason,
        details={
            "normalized_target": decision.normalized_target,
            "matched_scope": decision.matched_scope,
        },
    )

    return ScopeValidationResponse(
        target=decision.target,
        normalized_target=decision.normalized_target,
        allowed=decision.allowed,
        matched_scope=decision.matched_scope,
        reason=decision.reason,
    )
