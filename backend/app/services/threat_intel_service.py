from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_intel import IntelConflict, IntelSyncRun, ThreatIntelObservation, ThreatIntelSource
from app.services.threat_intel_clients import (
    ThreatIntelFetchError,
    fetch_cisa_kev,
    fetch_epss,
    fetch_nvd,
    fetch_osv,
)
from app.services.threat_intel_conflicts import rebuild_conflicts
from app.services.threat_intel_normalizers import (
    normalize_cisa_kev,
    normalize_epss,
    normalize_nvd,
    normalize_osv,
)
from app.services.threat_intel_types import NormalizedIntelRecord


SOURCE_DEFAULTS = {
    "nvd": {
        "name": "NVD",
        "source_type": "nvd",
        "cache_namespace": "nvd",
        "freshness_minutes": 1440,
    },
    "osv": {
        "name": "OSV",
        "source_type": "osv",
        "cache_namespace": "osv",
        "freshness_minutes": 1440,
    },
    "cisa-kev": {
        "name": "CISA KEV",
        "source_type": "cisa-kev",
        "cache_namespace": "cisa-kev",
        "freshness_minutes": 720,
    },
    "epss": {
        "name": "FIRST EPSS",
        "source_type": "epss",
        "cache_namespace": "epss",
        "freshness_minutes": 1440,
    },
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sha(raw: dict) -> str:
    payload = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ensure_default_sources(db: Session, settings) -> list[ThreatIntelSource]:
    urls = {
        "nvd": settings.nvd_cve_api_url,
        "osv": settings.osv_vulnerability_api_url,
        "cisa-kev": settings.cisa_kev_json_url,
        "epss": settings.first_epss_api_url,
    }
    rows = []
    for key, defaults in SOURCE_DEFAULTS.items():
        row = db.scalar(select(ThreatIntelSource).where(ThreatIntelSource.source_type == key))
        if row is None:
            row = ThreatIntelSource(
                name=defaults["name"],
                source_type=key,
                base_url=urls[key],
                enabled=True,
                freshness_minutes=defaults["freshness_minutes"],
                cache_namespace=defaults["cache_namespace"],
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            db.add(row)
            db.flush()
        elif row.base_url != urls[key]:
            row.base_url = urls[key]
            row.updated_at = utcnow()
        rows.append(row)
    db.commit()
    for row in rows:
        db.refresh(row)
    return rows


def _normalizer(source_type: str):
    return {
        "nvd": normalize_nvd,
        "osv": normalize_osv,
        "cisa-kev": normalize_cisa_kev,
        "epss": normalize_epss,
    }[source_type]


def _fetcher(source_type: str):
    return {
        "nvd": fetch_nvd,
        "osv": fetch_osv,
        "cisa-kev": fetch_cisa_kev,
        "epss": fetch_epss,
    }[source_type]


def _persist_record(
    db: Session,
    *,
    source: ThreatIntelSource,
    run: IntelSyncRun,
    record: NormalizedIntelRecord,
) -> ThreatIntelObservation | None:
    raw_sha = _sha(record.raw)

    existing = db.scalar(
        select(ThreatIntelObservation).where(
            ThreatIntelObservation.source_id == source.id,
            ThreatIntelObservation.canonical_id == record.canonical_id,
            ThreatIntelObservation.raw_sha256 == raw_sha,
        )
    )
    if existing is not None:
        return None

    row = ThreatIntelObservation(
        source_id=source.id,
        sync_run_id=run.id,
        canonical_id=record.canonical_id,
        cve_id=record.cve_id,
        osv_id=record.osv_id,
        cwes=record.cwes,
        cvss31_score=record.cvss31_score,
        cvss31_vector=record.cvss31_vector,
        cvss4_score=record.cvss4_score,
        cvss4_vector=record.cvss4_vector,
        cpes=record.cpes,
        affected_ranges=record.affected_ranges,
        fixed_ranges=record.fixed_ranges,
        references=record.references,
        published_at=record.published_at,
        modified_at=record.modified_at,
        kev=record.kev,
        epss=record.epss,
        epss_percentile=record.epss_percentile,
        vendor_advisories=record.vendor_advisories,
        known_ransomware_use=record.known_ransomware_use,
        required_action=record.required_action,
        confidence=record.confidence,
        raw_sha256=raw_sha,
        raw_json=record.raw,
        source_record_modified_at=record.source_record_modified_at,
        observed_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def sync_source(
    db: Session,
    *,
    source_type: str,
    identifiers: list[str],
    offline: bool,
    allow_cache_fallback: bool,
):
    source = db.scalar(select(ThreatIntelSource).where(ThreatIntelSource.source_type == source_type))
    if source is None:
        raise ValueError(f"Threat intelligence source '{source_type}' is not configured.")
    if not source.enabled:
        raise PermissionError(f"Threat intelligence source '{source.name}' is disabled.")

    run = IntelSyncRun(
        source_id=source.id,
        mode="offline-cache" if offline else "online",
        status="running",
        requested_identifiers=identifiers,
        started_at=utcnow(),
    )
    source.last_attempt_at = utcnow()
    source.last_error = None
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        result = _fetcher(source_type)(
            identifiers,
            offline=offline,
            allow_cache_fallback=allow_cache_fallback,
        )

        normalized: list[NormalizedIntelRecord] = []
        normalizer = _normalizer(source_type)
        for payload in result.payloads:
            normalized.extend(normalizer(payload))

        observations: list[ThreatIntelObservation] = []
        touched = set()
        for record in normalized:
            row = _persist_record(db, source=source, run=run, record=record)
            if row is not None:
                observations.append(row)
            touched.add(record.canonical_id)

        run.fetched_count = len(result.payloads)
        run.normalized_count = len(normalized)
        run.cache_used = result.cache_used
        run.status = "completed"
        run.completed_at = utcnow()

        source.last_success_at = utcnow()
        source.last_error = None
        source.updated_at = utcnow()

        for canonical_id in touched:
            rebuild_conflicts(db, canonical_id)

        db.commit()
        db.refresh(run)
        for row in observations:
            db.refresh(row)
        return run, observations

    except Exception as exc:
        run.status = "failed"
        run.error_message = str(exc)
        run.completed_at = utcnow()
        source.last_error = str(exc)
        source.updated_at = utcnow()
        db.commit()
        if isinstance(exc, (ThreatIntelFetchError, ValueError, PermissionError)):
            raise
        raise RuntimeError(str(exc)) from exc


def latest_observations_for(db: Session, canonical_id: str):
    rows = db.execute(
        select(ThreatIntelObservation, ThreatIntelSource)
        .join(ThreatIntelSource, ThreatIntelObservation.source_id == ThreatIntelSource.id)
        .where(ThreatIntelObservation.canonical_id == canonical_id)
        .order_by(ThreatIntelObservation.observed_at.desc())
    ).all()

    latest = {}
    for observation, source in rows:
        latest.setdefault(source.source_type, (observation, source))
    return list(latest.values())


def conflicts_for(db: Session, canonical_id: str) -> list[IntelConflict]:
    return list(
        db.scalars(
            select(IntelConflict)
            .where(IntelConflict.canonical_id == canonical_id)
            .order_by(IntelConflict.field_name)
        ).all()
    )
