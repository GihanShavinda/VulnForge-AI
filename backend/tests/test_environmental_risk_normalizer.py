import pytest

from app.services.environmental_risk_normalizer import normalize_factors


BASE = {
    "technical_severity_cvss": 6.5,
    "exploit_probability": 0.75,
    "known_exploitation": True,
    "network_exposure": "external",
    "service_reachability": "public",
    "asset_criticality": "critical",
    "attack_path_importance": "critical",
    "privilege_impact": "admin",
    "credential_exposure": "exposed",
    "security_control_strength": "weak",
    "patch_availability": "available",
    "threat_relevance": "active",
    "evidence_confidence": "confirmed",
    "lifecycle_risk": "legacy",
}


def test_normalizes_cvss_epss_and_kev():
    rows = normalize_factors(BASE)
    assert rows["technical_severity"].normalized_value == 65.0
    assert rows["exploit_probability"].normalized_value == 75.0
    assert rows["known_exploitation"].normalized_value == 100.0


def test_strong_control_becomes_low_risk_factor():
    raw = dict(BASE)
    raw["security_control_strength"] = "strong"
    rows = normalize_factors(raw)
    assert rows["security_control_weakness"].normalized_value == 0.0


def test_invalid_enum_fails_closed():
    raw = dict(BASE)
    raw["network_exposure"] = "mystery"
    with pytest.raises(ValueError):
        normalize_factors(raw)
