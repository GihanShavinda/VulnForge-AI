from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models.threat_intel import IntelConflict, ThreatIntelObservation, ThreatIntelSource


CONFLICT_FIELDS = (
    "cwe_list",
    "cvss31_score",
    "cvss31_vector",
    "cvss4_score",
    "cvss4_vector",
    "cpe_list",
    "published_at",
    "modified_at",
    "kev",
    "known_ransomware_use",
    "required_action",
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def detect_conflicting_values(source_values: dict[str, object]) -> bool:
    canonical = {
        json.dumps(value, sort_keys=True, default=str)
        for value in source_values.values()
        if value is not None and value != [] and value != ""
    }
    return len(canonical) > 1


def _value(obs: ThreatIntelObservation, field: str):
    if field == "cwe_list":
        return obs.cwes or None
    if field == "cpe_list":
        return obs.cpes or None
    value = getattr(obs, field)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def rebuild_conflicts(db: Session, canonical_id: str) -> list[IntelConflict]:
    db.execute(delete(IntelConflict).where(IntelConflict.canonical_id == canonical_id))

    rows = db.execute(
        select(ThreatIntelObservation, ThreatIntelSource.name)
        .join(ThreatIntelSource, ThreatIntelObservation.source_id == ThreatIntelSource.id)
        .where(ThreatIntelObservation.canonical_id == canonical_id)
        .order_by(ThreatIntelObservation.observed_at.desc())
    ).all()

    latest_by_source: dict[str, ThreatIntelObservation] = {}
    for obs, source_name in rows:
        latest_by_source.setdefault(source_name, obs)

    conflicts: list[IntelConflict] = []
    for field in CONFLICT_FIELDS:
        values = {}
        for source_name, obs in latest_by_source.items():
            value = _value(obs, field)
            if value is None or value == [] or value == "":
                continue
            values[source_name] = value

        if not detect_conflicting_values(values):
            continue

        conflict = IntelConflict(
            canonical_id=canonical_id,
            field_name=field,
            source_values=values,
            resolution_state="unresolved",
            resolution_note="Conflicting non-null source values are preserved; VulnForge does not invent a merged value.",
            detected_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(conflict)
        conflicts.append(conflict)

    db.flush()
    return conflicts
