from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.security_lab import Asset
from app.models.secret_exposure import SecretAttackPathSignal, SecretExposure, SecretScanImport
from app.services.gitleaks_parser import parse_gitleaks
from app.services.secret_patterns import scan_text
from app.services.secret_safety import evidence_hash, is_allowlisted, masked_fingerprint, sanitize_location


def _utcnow():
    return datetime.now(timezone.utc)


def _extract_candidates(source_type: str, payload, source_name: str) -> list[dict]:
    st=source_type.strip().lower()
    if st=="gitleaks":
        return parse_gitleaks(payload)
    if st in {"deterministic","repository","configuration","lab-artifact","test-repository"}:
        if isinstance(payload,dict):
            text=str(payload.get("text") or "")
            location=str(payload.get("location") or source_name)
        else:
            text=str(payload)
            location=source_name
        return scan_text(text,location)
    raise ValueError(f"Unsupported secret source type: {source_type}")


def import_secret_exposure(db: Session, *, asset_id, source_type: str, source_name: str, payload, allowlisted_hashes: list[str]):
    if asset_id is not None and db.get(Asset,asset_id) is None:
        raise ValueError("Asset not found.")

    run=SecretScanImport(asset_id=asset_id,source_type=source_type,source_name=source_name,status="running")
    db.add(run); db.flush()

    candidates=_extract_candidates(source_type,payload,source_name)
    findings=[]
    suppressed=0

    for c in candidates:
        raw=c["secret"]
        h=evidence_hash(raw)
        if is_allowlisted(raw,allowlisted_hashes):
            suppressed+=1
            continue

        loc=sanitize_location(c["location"])
        existing=db.scalar(
            select(SecretExposure).where(
                SecretExposure.import_id==run.id,
                SecretExposure.evidence_hash==h,
                SecretExposure.location==loc,
            )
        )
        if existing is not None:
            existing.last_seen=_utcnow()
            continue

        exposure=SecretExposure(
            import_id=run.id,
            secret_type=c["secret_type"],
            masked_fingerprint=masked_fingerprint(c["secret_type"],raw),
            location=loc,
            evidence_hash=h,
            severity=c["severity"],
            validation_status=c["validation_status"],
        )
        db.add(exposure); db.flush()
        findings.append(exposure)

        # Cross-asset reuse becomes an attack-path signal without exposing the secret.
        prior=db.execute(
            select(SecretExposure,SecretScanImport)
            .join(SecretScanImport,SecretExposure.import_id==SecretScanImport.id)
            .where(
                SecretExposure.evidence_hash==h,
                SecretExposure.id!=exposure.id,
                SecretScanImport.asset_id.is_not(None),
            )
        ).all()
        for other,other_run in prior:
            if asset_id is not None and other_run.asset_id!=asset_id:
                db.add(SecretAttackPathSignal(
                    exposure_id=exposure.id,
                    source_asset_id=asset_id,
                    related_asset_id=other_run.asset_id,
                    signal_type="credential_reuse_across_assets",
                    rationale="The same safely hashed credential fingerprint was observed on more than one asset.",
                    confidence="high confidence",
                ))

    run.status="completed"
    run.candidate_count=len(candidates)
    run.finding_count=len(findings)
    run.suppressed_count=suppressed
    db.commit(); db.refresh(run)
    for f in findings: db.refresh(f)
    return run,findings,suppressed


def list_imports(db: Session):
    return list(db.scalars(select(SecretScanImport).order_by(SecretScanImport.imported_at.desc())).all())


def list_findings(db: Session, import_id):
    return list(db.scalars(select(SecretExposure).where(SecretExposure.import_id==import_id).order_by(SecretExposure.first_seen.asc())).all())


def list_attack_path_signals(db: Session):
    return list(db.scalars(select(SecretAttackPathSignal).order_by(SecretAttackPathSignal.created_at.desc())).all())
