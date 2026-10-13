from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db
from app.models.threat_intel import IntelConflict, IntelSyncRun, ThreatIntelSource
from app.schemas.threat_intel import (
    IntelConflictRead,
    IntelSyncRequest,
    IntelSyncResult,
    IntelSyncRunRead,
    ThreatIntelDetail,
    ThreatIntelObservationView,
    ThreatIntelSourceRead,
)
from app.services.threat_intel_service import (
    conflicts_for,
    ensure_default_sources,
    latest_observations_for,
    sync_source,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intelligence"])


def _staleness(source: ThreatIntelSource):
    if source.last_success_at is None:
        return True, None
    now = datetime.now(timezone.utc)
    last = source.last_success_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    seconds = max(0, int((now - last).total_seconds()))
    stale = seconds > source.freshness_minutes * 60
    return stale, seconds


@router.get("/sources", response_model=list[ThreatIntelSourceRead])
def list_sources(db: Session = Depends(get_db)):
    ensure_default_sources(db, get_settings())
    return db.scalars(select(ThreatIntelSource).order_by(ThreatIntelSource.name)).all()


@router.post("/sync", response_model=IntelSyncResult, status_code=status.HTTP_201_CREATED)
def sync(payload: IntelSyncRequest, db: Session = Depends(get_db)):
    ensure_default_sources(db, get_settings())
    source_type = payload.source.strip().lower()
    aliases = {
        "nvd": "nvd",
        "osv": "osv",
        "cisa": "cisa-kev",
        "cisa-kev": "cisa-kev",
        "kev": "cisa-kev",
        "epss": "epss",
        "first-epss": "epss",
    }
    normalized = aliases.get(source_type)
    if normalized is None:
        raise HTTPException(status_code=422, detail="source must be one of: nvd, osv, cisa-kev, epss")

    try:
        run, observations = sync_source(
            db,
            source_type=normalized,
            identifiers=payload.identifiers,
            offline=payload.offline,
            allow_cache_fallback=payload.allow_cache_fallback,
        )
        return IntelSyncResult(run=run, observations=observations)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/sync-runs", response_model=list[IntelSyncRunRead])
def list_sync_runs(
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    return db.scalars(
        select(IntelSyncRun).order_by(IntelSyncRun.started_at.desc()).limit(limit)
    ).all()


@router.get("/vulnerabilities/{canonical_id}", response_model=ThreatIntelDetail)
def detail(canonical_id: str, db: Session = Depends(get_db)):
    ensure_default_sources(db, get_settings())
    pairs = latest_observations_for(db, canonical_id)
    observations = []
    for observation, source in pairs:
        stale, seconds = _staleness(source)
        observations.append(
            ThreatIntelObservationView(
                observation=observation,
                source=source.name,
                last_refresh=source.last_success_at,
                stale=stale,
                staleness_seconds=seconds,
                confidence=observation.confidence,
            )
        )
    return ThreatIntelDetail(
        canonical_id=canonical_id,
        observations=observations,
        conflicts=conflicts_for(db, canonical_id),
    )


@router.get("/conflicts", response_model=list[IntelConflictRead])
def list_conflicts(
    canonical_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    stmt = select(IntelConflict)
    if canonical_id:
        stmt = stmt.where(IntelConflict.canonical_id == canonical_id)
    return db.scalars(
        stmt.order_by(IntelConflict.detected_at.desc()).limit(limit)
    ).all()
