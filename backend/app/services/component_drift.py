from __future__ import annotations

from dataclasses import dataclass

from app.services.sbom_identity import component_identity_key
from app.services.sbom_types import NormalizedComponent


@dataclass(frozen=True)
class DriftDecision:
    identity_key: str
    change_type: str
    previous_version: str | None
    current_version: str | None


def detect_component_drift(previous: list[NormalizedComponent], current: list[NormalizedComponent]) -> list[DriftDecision]:
    previous_map = {component_identity_key(x): x for x in previous}
    current_map = {component_identity_key(x): x for x in current}
    events: list[DriftDecision] = []

    for key in sorted(current_map.keys() - previous_map.keys()):
        item = current_map[key]
        events.append(DriftDecision(key, "added", None, item.version))

    for key in sorted(previous_map.keys() - current_map.keys()):
        item = previous_map[key]
        events.append(DriftDecision(key, "removed", item.version, None))

    for key in sorted(previous_map.keys() & current_map.keys()):
        old = previous_map[key]
        new = current_map[key]
        if old.version != new.version:
            events.append(DriftDecision(key, "version_changed", old.version, new.version))

    return events
