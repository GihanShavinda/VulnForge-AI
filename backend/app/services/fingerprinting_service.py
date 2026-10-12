from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enumeration import EnumerationJob, ServiceObservation
from app.models.fingerprinting import FingerprintEvidence, FingerprintJob, Technology, TechnologyObservation
from app.models.security_lab import Asset, Network, ScanScope
from app.schemas.fingerprinting import AuthenticatedInventoryItem
from app.services.discovery_scope import validate_discovery_target
from app.services.fingerprint_confidence import FingerprintCandidate, aggregate_candidates
from app.services.fingerprint_parser import candidates_from_http_headers, candidates_from_service_observations, candidates_from_whatweb, parse_nmap_os_xml
from app.services.http_fingerprint import fetch_http_headers
from app.services.nmap_os_runner import run_nmap_os_detection
from app.services.whatweb_runner import run_whatweb


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _approved_scopes(db: Session) -> list[ScanScope]:
    return list(db.scalars(select(ScanScope).join(Network, ScanScope.network_id == Network.id).where(ScanScope.enabled.is_(True), Network.approved_for_scanning.is_(True))).all())


def _latest_service_rows(db: Session, asset_id) -> list[ServiceObservation]:
    """Use the newest completed V3 baseline for each transport protocol."""
    rows: list[ServiceObservation] = []
    for protocol in ("tcp", "udp"):
        latest_job = db.scalar(
            select(EnumerationJob)
            .where(
                EnumerationJob.asset_id == asset_id,
                EnumerationJob.protocol == protocol,
                EnumerationJob.status == "completed",
            )
            .order_by(
                EnumerationJob.completed_at.desc().nullslast(),
                EnumerationJob.created_at.desc(),
            )
            .limit(1)
        )
        if latest_job is not None:
            rows.extend(
                db.scalars(
                    select(ServiceObservation).where(
                        ServiceObservation.enumeration_job_id == latest_job.id
                    )
                ).all()
            )
    return rows


def _http_urls(asset: Asset, services: list[ServiceObservation]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for service in services:
        if service.state != "open":
            continue
        name = (service.service or "").lower()
        if service.tls_indicator or name in {"https", "https-alt", "ssl"}:
            scheme = "https"
        elif name in {"http", "http-alt", "http-proxy"} or service.port in {80, 8000, 8008, 8080, 8081}:
            scheme = "http"
        else:
            continue
        default_port = 443 if scheme == "https" else 80
        suffix = "" if service.port == default_port else f":{service.port}"
        url = f"{scheme}://{asset.ip_address}{suffix}/"
        if url not in seen:
            urls.append(url); seen.add(url)
    return urls


def _legacy_status(name: str, version: str | None) -> tuple[bool | None, str | None]:
    normalized = name.strip().lower()
    if normalized == "windows xp":
        return True, "Windows XP is treated as a legacy operating system; this lifecycle flag is separate from CVE assessment."
    if normalized == "windows 7":
        return True, "Windows 7 is treated as a legacy operating system; this lifecycle flag is separate from CVE assessment."
    if normalized == "windows 10":
        return None, "Windows 10 lifecycle depends on edition/channel; V4 does not infer unsupported status without edition evidence."
    if normalized == "ubuntu":
        if version and version.split(".", 1)[0].isdigit() and int(version.split(".", 1)[0]) < 20:
            return True, "This Ubuntu release is treated as legacy for standard-support review; ESM/subscription status is not inferred."
        return None, "Ubuntu lifecycle requires an exact release and support-channel context."
    return None, None


def _technology(db: Session, category: str, name: str) -> Technology:
    key = f"{category}:{' '.join(name.strip().lower().split())}"
    existing = db.scalar(select(Technology).where(Technology.canonical_key == key))
    if existing:
        return existing
    row = Technology(canonical_key=key, name=name, category=category)
    db.add(row); db.flush(); return row


def _make_evidence(job_id, asset_id, candidate: FingerprintCandidate) -> FingerprintEvidence:
    raw = candidate.raw_evidence
    return FingerprintEvidence(fingerprint_job_id=job_id, asset_id=asset_id, source_type=candidate.source_type, source_locator=candidate.source_locator, observed_value=candidate.observed_value, version_evidence=candidate.version, confidence=candidate.confidence, raw_evidence=raw, content_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(), captured_at=_utcnow())


def execute_fingerprinting(db: Session, *, asset_id, explicitly_authorized: bool, run_nmap_os: bool, run_whatweb_enabled: bool, collect_http_headers: bool, authenticated_inventory: list[AuthenticatedInventoryItem]) -> tuple[FingerprintJob, list[TechnologyObservation], list[FingerprintEvidence]]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise ValueError("Asset not found.")
    if not asset.scanning_enabled:
        raise PermissionError("Asset scanning is disabled.")

    decision = validate_discovery_target(asset.ip_address, _approved_scopes(db), explicitly_authorized=explicitly_authorized)
    if not decision.allowed or decision.normalized_target is None:
        raise PermissionError(decision.reason)

    job = FingerprintJob(asset_id=asset.id, target=decision.normalized_target, status="running", explicitly_authorized=explicitly_authorized, run_nmap_os=run_nmap_os, run_whatweb=run_whatweb_enabled, collect_http_headers=collect_http_headers, started_at=_utcnow())
    db.add(job); db.commit(); db.refresh(job)

    warnings: list[str] = []
    candidates: list[FingerprintCandidate] = []
    evidence_rows: list[FingerprintEvidence] = []

    try:
        service_rows = _latest_service_rows(db, asset.id)
        service_candidates = candidates_from_service_observations(service_rows)
        candidates.extend(service_candidates)
        evidence_rows.extend(_make_evidence(job.id, asset.id, c) for c in service_candidates)

        if run_nmap_os:
            try:
                result = run_nmap_os_detection(decision.normalized_target)
                raw = result.xml_text
                evidence_rows.append(FingerprintEvidence(fingerprint_job_id=job.id, asset_id=asset.id, source_type="nmap_os", source_locator="nmap-os-xml", observed_value="Nmap OS detection XML", version_evidence=None, confidence="unknown", raw_evidence=raw, content_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(), captured_at=_utcnow()))
                parsed_os = parse_nmap_os_xml(raw)
                candidates.extend(parsed_os)
                evidence_rows.extend(_make_evidence(job.id, asset.id, c) for c in parsed_os)
            except RuntimeError as exc:
                warnings.append(str(exc))

        urls = _http_urls(asset, service_rows)
        if collect_http_headers:
            for url in urls:
                result = fetch_http_headers(url)
                evidence_rows.append(FingerprintEvidence(fingerprint_job_id=job.id, asset_id=asset.id, source_type="http_header", source_locator=url, observed_value=json.dumps(result.headers, sort_keys=True), version_evidence=None, confidence="medium confidence" if result.headers else "unknown", raw_evidence=result.raw_evidence, content_sha256=hashlib.sha256(result.raw_evidence.encode("utf-8")).hexdigest(), captured_at=_utcnow()))
                header_candidates = candidates_from_http_headers(result.headers, source_locator=url, raw_evidence=result.raw_evidence)
                candidates.extend(header_candidates)
                evidence_rows.extend(_make_evidence(job.id, asset.id, c) for c in header_candidates)
                if result.error:
                    warnings.append(f"HTTP header collection failed for {url}: {result.error}")

        if run_whatweb_enabled:
            for url in urls:
                try:
                    result = run_whatweb(url)
                    raw = result.raw_text or json.dumps({"url": url, "payload": result.payload}, sort_keys=True)
                    evidence_rows.append(FingerprintEvidence(fingerprint_job_id=job.id, asset_id=asset.id, source_type="whatweb", source_locator=url, observed_value=raw[:2000], version_evidence=None, confidence="medium confidence" if raw.strip() else "unknown", raw_evidence=raw, content_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(), captured_at=_utcnow()))
                    whatweb_candidates = candidates_from_whatweb(result.payload, source_locator=url, raw_evidence=raw)
                    candidates.extend(whatweb_candidates)
                    evidence_rows.extend(_make_evidence(job.id, asset.id, c) for c in whatweb_candidates)
                except RuntimeError as exc:
                    warnings.append(str(exc)); break

        for item in authenticated_inventory:
            raw = json.dumps(item.model_dump(mode="json"), sort_keys=True)
            c = FingerprintCandidate(item.category, item.name.strip(), item.version.strip() if item.version else None, "confirmed", "authenticated_inventory", item.observed_value or raw, "authenticated-inventory", raw)
            candidates.append(c); evidence_rows.append(_make_evidence(job.id, asset.id, c))

        for e in evidence_rows:
            db.add(e)
        db.flush()

        observations: list[TechnologyObservation] = []
        for aggregate in aggregate_candidates(candidates):
            tech = _technology(db, aggregate.category, aggregate.name)
            legacy, note = _legacy_status(aggregate.name, aggregate.version)
            summary = {"sources": sorted({c.source_type for c in aggregate.candidates}), "candidate_count": len(aggregate.candidates), "version_supported_by_evidence": bool(aggregate.version), "conflict_state": aggregate.conflict_state}
            row = TechnologyObservation(fingerprint_job_id=job.id, asset_id=asset.id, technology_id=tech.id, observed_name=aggregate.name, observed_version=aggregate.version, confidence=aggregate.confidence, conflict_state=aggregate.conflict_state, is_preferred=aggregate.is_preferred, is_legacy=legacy, lifecycle_note=note, evidence_summary_json=json.dumps(summary, sort_keys=True), first_seen=_utcnow(), last_seen=_utcnow())
            db.add(row); db.flush(); observations.append(row)
            signatures = {(c.source_type, c.source_locator, c.observed_value, c.version) for c in aggregate.candidates}
            for evidence in evidence_rows:
                if (evidence.source_type, evidence.source_locator, evidence.observed_value, evidence.version_evidence) in signatures:
                    evidence.technology_observation_id = row.id

        job.status = "completed_with_warnings" if warnings else "completed"
        job.warning_message = "\n".join(warnings) if warnings else None
        job.completed_at = _utcnow()
        db.commit(); db.refresh(job)
        for row in observations: db.refresh(row)
        for row in evidence_rows: db.refresh(row)
        return job, observations, evidence_rows
    except Exception as exc:
        db.rollback()
        failed = db.get(FingerprintJob, job.id)
        if failed:
            failed.status = "failed"; failed.error_message = str(exc); failed.completed_at = _utcnow(); db.commit()
        raise
