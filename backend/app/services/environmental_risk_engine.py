from __future__ import annotations

from dataclasses import dataclass

from app.services.environmental_risk_normalizer import normalize_factors


@dataclass(frozen=True)
class RiskContribution:
    factor_name: str
    contribution_type: str
    raw_value: object
    normalized_value: float | None
    configured_weight: float | None
    contribution: float
    reason: str
    sequence: int


@dataclass(frozen=True)
class RiskCalculation:
    raw_factors: dict
    normalized_factors: dict
    weights: dict
    contributions: list[RiskContribution]
    base_score: float
    interaction_adjustment: float
    final_score: float
    priority_tier: str
    rationale: str


def priority_for_score(score: float) -> str:
    if score >= 85.0:
        return "P0"
    if score >= 70.0:
        return "P1"
    if score >= 50.0:
        return "P2"
    if score >= 30.0:
        return "P3"
    return "P4"


def _special_interactions(
    raw: dict,
    normalized: dict[str, float],
    interaction_rules: dict,
    start_sequence: int,
) -> tuple[list[RiskContribution], float]:
    rows: list[RiskContribution] = []
    adjustment = 0.0
    sequence = start_sequence

    exposed = raw["network_exposure"] == "external"
    reachable = raw["service_reachability"] in {"reachable", "public"}
    kev = bool(raw["known_exploitation"])
    critical_path = raw["attack_path_importance"] == "critical"

    if exposed and reachable and kev and critical_path:
        bonus = float(
            interaction_rules.get(
                "exposed_kev_critical_path_bonus",
                0.0,
            )
        )
        adjustment += bonus
        rows.append(
            RiskContribution(
                factor_name="interaction.exposed_kev_critical_path",
                contribution_type="interaction",
                raw_value={
                    "network_exposure": raw["network_exposure"],
                    "service_reachability": raw["service_reachability"],
                    "known_exploitation": kev,
                    "attack_path_importance": raw["attack_path_importance"],
                },
                normalized_value=None,
                configured_weight=None,
                contribution=bonus,
                reason=(
                    "Context bonus because an externally exposed and reachable asset "
                    "has known exploitation and sits on a critical attack path."
                ),
                sequence=sequence,
            )
        )
        sequence += 1

    isolated = raw["network_exposure"] == "isolated"
    not_reachable = raw["service_reachability"] == "none"
    strong_control = raw["security_control_strength"] == "strong"

    if isolated and not_reachable and strong_control:
        penalty = float(
            interaction_rules.get(
                "isolated_nonreachable_strong_control_penalty",
                0.0,
            )
        )
        adjustment += penalty
        rows.append(
            RiskContribution(
                factor_name="interaction.isolated_nonreachable_strong_control",
                contribution_type="interaction",
                raw_value={
                    "network_exposure": raw["network_exposure"],
                    "service_reachability": raw["service_reachability"],
                    "security_control_strength": raw["security_control_strength"],
                },
                normalized_value=None,
                configured_weight=None,
                contribution=penalty,
                reason=(
                    "Context reduction because the asset is isolated, not reachable, "
                    "and protected by a strong compensating control."
                ),
                sequence=sequence,
            )
        )

    return rows, adjustment


def calculate_environmental_risk(
    raw_factors: dict,
    weights: dict[str, float],
    interaction_rules: dict,
) -> RiskCalculation:
    normalized_objects = normalize_factors(raw_factors)
    normalized = {
        name: item.normalized_value
        for name, item in normalized_objects.items()
    }

    contributions: list[RiskContribution] = []
    base_score = 0.0

    for sequence, (name, item) in enumerate(normalized_objects.items(), start=1):
        weight = float(weights[name])
        contribution = item.normalized_value * weight
        base_score += contribution
        contributions.append(
            RiskContribution(
                factor_name=name,
                contribution_type="factor",
                raw_value=item.raw_value,
                normalized_value=item.normalized_value,
                configured_weight=weight,
                contribution=round(contribution, 4),
                reason=item.reason,
                sequence=sequence,
            )
        )

    interaction_rows, interaction_adjustment = _special_interactions(
        raw_factors,
        normalized,
        interaction_rules,
        start_sequence=len(contributions) + 1,
    )
    contributions.extend(interaction_rows)

    final_score = max(
        0.0,
        min(
            100.0,
            base_score + interaction_adjustment,
        ),
    )
    final_score = round(final_score, 2)
    base_score = round(base_score, 2)
    interaction_adjustment = round(interaction_adjustment, 2)

    priority = priority_for_score(final_score)

    rationale = (
        "Experimental Environmental Risk Score 2.0 combines technical severity "
        "with exploitability, exposure, asset context, attack-path importance, "
        "credential exposure, control strength, patch posture, threat relevance, "
        "evidence confidence, and lifecycle risk. It must not be interpreted as "
        "CVSS or as proof of exploit success."
    )

    return RiskCalculation(
        raw_factors=raw_factors,
        normalized_factors=normalized,
        weights=weights,
        contributions=contributions,
        base_score=base_score,
        interaction_adjustment=interaction_adjustment,
        final_score=final_score,
        priority_tier=priority,
        rationale=rationale,
    )
