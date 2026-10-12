from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

CONFIDENCE_ORDER = {"unknown": 0, "low confidence": 1, "medium confidence": 2, "high confidence": 3, "confirmed": 4}
SOURCE_PRIORITY = {"authenticated_inventory": 100, "service_banner": 80, "nmap_os": 75, "http_header": 65, "whatweb": 60, "service_name": 40}


@dataclass(frozen=True)
class FingerprintCandidate:
    category: str
    name: str
    version: str | None
    confidence: str
    source_type: str
    observed_value: str
    source_locator: str | None
    raw_evidence: str


@dataclass(frozen=True)
class AggregatedFingerprint:
    category: str
    name: str
    version: str | None
    confidence: str
    conflict_state: str
    is_preferred: bool
    candidates: tuple[FingerprintCandidate, ...]


def normalize_name(value: str) -> str:
    return " ".join(value.strip().lower().split())


def confidence_rank(value: str) -> int:
    return CONFIDENCE_ORDER.get(value, 0)


def _candidate_sort_key(candidate: FingerprintCandidate) -> tuple[int, int, int]:
    return (confidence_rank(candidate.confidence), SOURCE_PRIORITY.get(candidate.source_type, 0), 1 if candidate.version else 0)


def aggregate_candidates(candidates: Iterable[FingerprintCandidate]) -> list[AggregatedFingerprint]:
    grouped: dict[tuple[str, str], list[FingerprintCandidate]] = defaultdict(list)
    category_names: dict[str, set[str]] = defaultdict(set)

    for candidate in candidates:
        key = (candidate.category, normalize_name(candidate.name))
        grouped[key].append(candidate)
        category_names[candidate.category].add(normalize_name(candidate.name))

    results: list[AggregatedFingerprint] = []
    for (category, _), group in grouped.items():
        ordered = sorted(group, key=_candidate_sort_key, reverse=True)
        best = ordered[0]
        nonempty_versions = {x.version.strip() for x in group if x.version and x.version.strip()}
        strongest_rank = max(confidence_rank(x.confidence) for x in group)
        strongest_versions = {x.version.strip() for x in group if x.version and x.version.strip() and confidence_rank(x.confidence) == strongest_rank}

        if len(strongest_versions) == 1:
            version = next(iter(strongest_versions))
        elif len(strongest_versions) > 1:
            version = None
        elif len(nonempty_versions) == 1:
            version = next(iter(nonempty_versions))
        else:
            version = None

        version_conflict = len(nonempty_versions) > 1
        category_conflict = category == "operating_system" and len(category_names[category]) > 1
        results.append(AggregatedFingerprint(category, best.name, version, best.confidence, "conflicting" if version_conflict or category_conflict else "none", False, tuple(group)))

    by_category: dict[str, list[int]] = defaultdict(list)
    for i, item in enumerate(results):
        by_category[item.category].append(i)

    mutable = list(results)
    for indexes in by_category.values():
        preferred_index = max(indexes, key=lambda i: (confidence_rank(mutable[i].confidence), max(SOURCE_PRIORITY.get(c.source_type, 0) for c in mutable[i].candidates), 1 if mutable[i].version else 0))
        old = mutable[preferred_index]
        mutable[preferred_index] = AggregatedFingerprint(old.category, old.name, old.version, old.confidence, old.conflict_state, True, old.candidates)

    return mutable
