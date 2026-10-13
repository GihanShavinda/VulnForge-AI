from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.authenticated_assessment import AuthenticatedEvidence, AuthenticatedScan, CredentialUseAudit
from app.models.security_lab import Asset, CredentialProfile, Network, ScanScope
from app.models.fingerprinting import FingerprintJob, TechnologyObservation
from app.schemas.authenticated_assessment import ImportedEvidenceItem
from app.services.credential_crypto import decrypt_secret
from app.services.credential_guard import ensure_credential_usable, record_auth_failure, record_auth_success
from app.services.discovery_scope import validate_discovery_target
from app.services.ssh_collector import SSHAuthenticationError, collect_linux_ssh
from app.services.winrm_collector import WinRMAuthenticationError, collect_windows_winrm


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _approved_scopes(db: Session) -> list[ScanScope]:
    return list(db.scalars(select(ScanScope).join(Network, ScanScope.network_id==Network.id).where(ScanScope.enabled.is_(True), Network.approved_for_scanning.is_(True))).all())


def _audit(db: Session, profile: CredentialProfile, asset: Asset, scan: AuthenticatedScan | None, outcome: str, reason: str | None):
    row=CredentialUseAudit(credential_profile_id=profile.id, asset_id=asset.id, authenticated_scan_id=scan.id if scan else None, outcome=outcome, reason=reason, remote_address=asset.ip_address)
    db.add(row)
    return row


def _legacy_windows(db: Session, asset: Asset) -> bool:
    text=(asset.operating_system or "").lower()
    if "windows 7" in text or "windows xp" in text:
        return True
    latest_job=db.scalar(
        select(FingerprintJob)
        .where(FingerprintJob.asset_id==asset.id, FingerprintJob.status.in_(["completed","completed_with_warnings"]))
        .order_by(FingerprintJob.completed_at.desc().nullslast(), FingerprintJob.created_at.desc())
        .limit(1)
    )
    if latest_job is None:
        return False
    preferred=db.scalar(
        select(TechnologyObservation)
        .where(TechnologyObservation.fingerprint_job_id==latest_job.id, TechnologyObservation.is_preferred.is_(True))
        .limit(1)
    )
    observed=(preferred.observed_name if preferred else "").lower()
    return observed in {"windows 7", "windows xp"}


def execute_authenticated_scan(db: Session, *, asset_id, credential_profile_id, explicitly_authorized: bool):
    asset=db.get(Asset, asset_id)
    if asset is None: raise ValueError("Asset not found.")
    if not asset.scanning_enabled: raise PermissionError("Asset scanning is disabled.")
    profile=db.get(CredentialProfile, credential_profile_id)
    if profile is None: raise ValueError("Credential profile not found.")
    ensure_credential_usable(profile)
    decision=validate_discovery_target(asset.ip_address, _approved_scopes(db), explicitly_authorized=explicitly_authorized)
    if not decision.allowed: raise PermissionError(decision.reason)
    if profile.protocol == "winrm" and _legacy_windows(db, asset):
        raise PermissionError("Remote automation is disabled for legacy Windows assets. Use the imported-evidence V5 endpoint instead.")

    transport=profile.protocol.lower()
    if transport not in {"ssh","winrm"}: raise ValueError("V5 supports SSH or WinRM credential profiles.")
    scan=AuthenticatedScan(asset_id=asset.id, credential_profile_id=profile.id, transport=transport, collection_mode="remote", status="running", explicitly_authorized=explicitly_authorized, started_at=utcnow())
    db.add(scan); db.commit(); db.refresh(scan)

    try:
        secret=decrypt_secret(profile.encrypted_secret or "")
        if transport=="ssh":
            items=collect_linux_ssh(asset.ip_address, profile.username or "", secret, profile.port or 22)
        else:
            items=collect_windows_winrm(asset.ip_address, profile.username or "", secret, profile.port or 5985)
        record_auth_success(profile)
        _audit(db, profile, asset, scan, "success", None)
        evidence=[]
        for item in items:
            value=item.value or ""
            row=AuthenticatedEvidence(authenticated_scan_id=scan.id, asset_id=asset.id, category=item.category, source_type=transport, source_locator=item.locator, observed_value=value, confidence="confirmed", content_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(), captured_at=utcnow())
            db.add(row); evidence.append(row)
        scan.status="completed"; scan.completed_at=utcnow(); db.commit()
        db.refresh(scan)
        for row in evidence: db.refresh(row)
        return scan,evidence
    except (SSHAuthenticationError, WinRMAuthenticationError) as exc:
        record_auth_failure(profile); _audit(db, profile, asset, scan, "authentication_failed", str(exc))
        scan.status="authentication_failed"; scan.error_message=str(exc); scan.completed_at=utcnow(); db.commit()
        raise PermissionError(str(exc)) from exc
    except Exception as exc:
        db.rollback(); failed=db.get(AuthenticatedScan, scan.id)
        if failed:
            failed.status="failed"; failed.error_message=str(exc); failed.completed_at=utcnow(); db.commit()
        raise


def import_authenticated_evidence(db: Session, *, asset_id, source_name: str, explicitly_authorized: bool, evidence_items: list[ImportedEvidenceItem]):
    asset=db.get(Asset, asset_id)
    if asset is None: raise ValueError("Asset not found.")
    decision=validate_discovery_target(asset.ip_address, _approved_scopes(db), explicitly_authorized=explicitly_authorized)
    if not decision.allowed: raise PermissionError(decision.reason)
    scan=AuthenticatedScan(asset_id=asset.id, credential_profile_id=None, transport="import", collection_mode="imported", status="completed", explicitly_authorized=explicitly_authorized, started_at=utcnow(), completed_at=utcnow())
    db.add(scan); db.flush()
    rows=[]
    for item in evidence_items:
        value=item.observed_value
        row=AuthenticatedEvidence(authenticated_scan_id=scan.id, asset_id=asset.id, category=item.category, source_type="imported_authenticated_inventory", source_locator=item.source_locator or source_name, observed_value=value, confidence="confirmed", content_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(), captured_at=utcnow())
        db.add(row); rows.append(row)
    db.commit(); db.refresh(scan)
    for row in rows: db.refresh(row)
    return scan, rows
