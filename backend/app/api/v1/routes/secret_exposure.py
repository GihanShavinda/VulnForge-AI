from __future__ import annotations
import uuid
from fastapi import APIRouter,Depends,HTTPException,status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.secret_exposure import (
    SecretAttackPathSignalRead,SecretExposureRead,SecretImportRequest,
    SecretImportResult,SecretScanImportRead,
)
from app.services.secret_exposure_service import (
    import_secret_exposure,list_attack_path_signals,list_findings,list_imports,
)

router=APIRouter(prefix="/secret-exposure",tags=["secret-exposure-assessment"])

@router.post("/imports",response_model=SecretImportResult,status_code=status.HTTP_201_CREATED)
def create_import(payload: SecretImportRequest,db: Session=Depends(get_db)):
    try:
        run,findings,suppressed=import_secret_exposure(
            db,asset_id=payload.asset_id,source_type=payload.source_type,
            source_name=payload.source_name,payload=payload.payload,
            allowlisted_hashes=payload.allowlisted_hashes,
        )
        return SecretImportResult(run=run,findings=findings,suppressed_count=suppressed)
    except (ValueError,TypeError) as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc

@router.get("/imports",response_model=list[SecretScanImportRead])
def imports(db: Session=Depends(get_db)):
    return list_imports(db)

@router.get("/imports/{import_id}/findings",response_model=list[SecretExposureRead])
def findings(import_id: uuid.UUID,db: Session=Depends(get_db)):
    return list_findings(db,import_id)

@router.get("/attack-path-signals",response_model=list[SecretAttackPathSignalRead])
def attack_path_signals(db: Session=Depends(get_db)):
    return list_attack_path_signals(db)
