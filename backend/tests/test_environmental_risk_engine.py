from app.services.environmental_risk_defaults import (
    DEFAULT_INTERACTION_RULES,
    DEFAULT_WEIGHTS,
)
from app.services.environmental_risk_engine import (
    calculate_environmental_risk,
    priority_for_score,
)


def _medium_exposed_kev_critical_path():
    return {
        "technical_severity_cvss": 6.0,
        "exploit_probability": 0.90,
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


def _critical_isolated_strong_control():
    return {
        "technical_severity_cvss": 10.0,
        "exploit_probability": 0.05,
        "known_exploitation": False,
        "network_exposure": "isolated",
        "service_reachability": "none",
        "asset_criticality": "medium",
        "attack_path_importance": "low",
        "privilege_impact": "low",
        "credential_exposure": "none",
        "security_control_strength": "strong",
        "patch_availability": "applied",
        "threat_relevance": "low",
        "evidence_confidence": "confirmed",
        "lifecycle_risk": "supported",
    }


def test_medium_cvss_context_can_outrank_critical_isolated_context():
    contextual = calculate_environmental_risk(
        _medium_exposed_kev_critical_path(),
        DEFAULT_WEIGHTS,
        DEFAULT_INTERACTION_RULES,
    )
    isolated = calculate_environmental_risk(
        _critical_isolated_strong_control(),
        DEFAULT_WEIGHTS,
        DEFAULT_INTERACTION_RULES,
    )

    assert contextual.final_score > isolated.final_score


def test_stores_one_factor_contribution_per_weight():
    result = calculate_environmental_risk(
        _medium_exposed_kev_critical_path(),
        DEFAULT_WEIGHTS,
        DEFAULT_INTERACTION_RULES,
    )

    factor_rows = [
        row for row in result.contributions
        if row.contribution_type == "factor"
    ]

    assert len(factor_rows) == len(DEFAULT_WEIGHTS)
    assert set(result.normalized_factors) == set(DEFAULT_WEIGHTS)


def test_special_bonus_is_recorded():
    result = calculate_environmental_risk(
        _medium_exposed_kev_critical_path(),
        DEFAULT_WEIGHTS,
        DEFAULT_INTERACTION_RULES,
    )

    names = {row.factor_name for row in result.contributions}
    assert "interaction.exposed_kev_critical_path" in names
    assert result.interaction_adjustment > 0


def test_isolated_strong_control_reduction_is_recorded():
    result = calculate_environmental_risk(
        _critical_isolated_strong_control(),
        DEFAULT_WEIGHTS,
        DEFAULT_INTERACTION_RULES,
    )

    names = {row.factor_name for row in result.contributions}
    assert "interaction.isolated_nonreachable_strong_control" in names
    assert result.interaction_adjustment < 0


def test_priority_tiers():
    assert priority_for_score(90) == "P0"
    assert priority_for_score(75) == "P1"
    assert priority_for_score(55) == "P2"
    assert priority_for_score(35) == "P3"
    assert priority_for_score(10) == "P4"


def test_score_is_bounded_0_to_100():
    result = calculate_environmental_risk(
        _medium_exposed_kev_critical_path(),
        DEFAULT_WEIGHTS,
        {
            "exposed_kev_critical_path_bonus": 999.0,
            "isolated_nonreachable_strong_control_penalty": -20.0,
        },
    )
    assert result.final_score == 100.0
