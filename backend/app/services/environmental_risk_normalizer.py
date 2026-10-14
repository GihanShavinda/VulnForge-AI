from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizedFactor:
    raw_value: object
    normalized_value: float
    reason: str


ENUM_MAPS = {
    "network_exposure": {
        "isolated": 0.0,
        "internal": 40.0,
        "adjacent": 65.0,
        "external": 100.0,
    },
    "service_reachability": {
        "none": 0.0,
        "segmented": 25.0,
        "reachable": 70.0,
        "public": 100.0,
    },
    "asset_criticality": {
        "low": 20.0,
        "medium": 50.0,
        "high": 80.0,
        "critical": 100.0,
    },
    "attack_path_importance": {
        "none": 0.0,
        "low": 25.0,
        "medium": 50.0,
        "high": 80.0,
        "critical": 100.0,
    },
    "privilege_impact": {
        "none": 0.0,
        "low": 25.0,
        "user": 45.0,
        "admin": 85.0,
        "system": 100.0,
    },
    "credential_exposure": {
        "none": 0.0,
        "possible": 35.0,
        "exposed": 75.0,
        "reused_privileged": 100.0,
    },
    "security_control_weakness": {
        "strong": 0.0,
        "medium": 40.0,
        "weak": 75.0,
        "none": 100.0,
    },
    "patch_unavailability": {
        "applied": 0.0,
        "available": 50.0,
        "unknown": 60.0,
        "no_patch": 100.0,
    },
    "threat_relevance": {
        "low": 20.0,
        "medium": 50.0,
        "high": 80.0,
        "active": 100.0,
    },
    "evidence_confidence": {
        "unknown": 20.0,
        "low": 40.0,
        "medium": 60.0,
        "high": 80.0,
        "confirmed": 100.0,
    },
    "lifecycle_risk": {
        "supported": 0.0,
        "limited": 35.0,
        "legacy": 65.0,
        "eol": 90.0,
        "unsupported": 100.0,
    },
}


def _enum_factor(name: str, raw_value: str) -> NormalizedFactor:
    table = ENUM_MAPS[name]
    if raw_value not in table:
        raise ValueError(
            f"Unsupported value for {name}: {raw_value}. "
            f"Allowed values: {', '.join(table)}"
        )
    return NormalizedFactor(
        raw_value=raw_value,
        normalized_value=table[raw_value],
        reason=f"{name} mapped from '{raw_value}' to {table[raw_value]:.1f}/100.",
    )


def normalize_factors(raw: dict) -> dict[str, NormalizedFactor]:
    result: dict[str, NormalizedFactor] = {}

    cvss = float(raw["technical_severity_cvss"])
    result["technical_severity"] = NormalizedFactor(
        raw_value=cvss,
        normalized_value=round(cvss * 10.0, 3),
        reason="CVSS technical severity normalized from 0-10 to 0-100.",
    )

    epss = float(raw["exploit_probability"])
    result["exploit_probability"] = NormalizedFactor(
        raw_value=epss,
        normalized_value=round(epss * 100.0, 3),
        reason="Exploit probability normalized from 0-1 to 0-100.",
    )

    kev = bool(raw["known_exploitation"])
    result["known_exploitation"] = NormalizedFactor(
        raw_value=kev,
        normalized_value=100.0 if kev else 0.0,
        reason="Known exploitation contributes 100 when present and 0 when absent.",
    )

    mappings = {
        "network_exposure": raw["network_exposure"],
        "service_reachability": raw["service_reachability"],
        "asset_criticality": raw["asset_criticality"],
        "attack_path_importance": raw["attack_path_importance"],
        "privilege_impact": raw["privilege_impact"],
        "credential_exposure": raw["credential_exposure"],
        "security_control_weakness": raw["security_control_strength"],
        "patch_unavailability": raw["patch_availability"],
        "threat_relevance": raw["threat_relevance"],
        "evidence_confidence": raw["evidence_confidence"],
        "lifecycle_risk": raw["lifecycle_risk"],
    }

    for name, value in mappings.items():
        result[name] = _enum_factor(name, str(value))

    return result
