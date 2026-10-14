from __future__ import annotations
from dataclasses import dataclass
from datetime import date
from app.services.security_control_matrix import EFFECT_MULTIPLIERS, determine_control_effect

@dataclass(frozen=True)
class EvaluatedControl:
    control_id: object
    control_type: str
    owner: str
    effect: str
    effectiveness: float
    confidence: float
    effective_mitigation: float
    evidence: dict
    expired: bool
    temporary: bool
    expires_at: date | None
    mitigation_until: date | None
    reason: str

@dataclass(frozen=True)
class ResidualRiskCalculation:
    inherent_risk: float
    combined_control_effectiveness: float
    combined_control_confidence: float
    residual_risk: float
    controls: list[EvaluatedControl]
    rationale: str

def _is_inactive(control, today: date) -> bool:
    if not control.enabled:
        return True
    if control.effective_from and control.effective_from > today:
        return True
    if control.expires_at and control.expires_at < today:
        return True
    if control.temporary and control.mitigation_until and control.mitigation_until < today:
        return True
    return False

def calculate_residual_risk(*, inherent_risk: float, exposure_type: str, controls: list, today: date | None = None) -> ResidualRiskCalculation:
    today = today or date.today()
    evaluated = []
    remaining = 1.0
    eff_values = []
    conf_values = []

    for control in controls:
        effect = determine_control_effect(control.control_type, exposure_type)
        expired = _is_inactive(control, today)
        if expired:
            mitigation = 0.0
            reason = "Control is disabled, not yet effective, expired, or its temporary mitigation date has passed."
        elif effect == "does_not_affect":
            mitigation = 0.0
            reason = f"{control.control_type} does not materially affect {exposure_type}."
        else:
            mitigation = (control.effectiveness/100.0) * (control.confidence/100.0) * EFFECT_MULTIPLIERS[effect]
            mitigation = max(0.0, min(0.90, mitigation))
            remaining *= 1.0 - mitigation
            eff_values.append(control.effectiveness)
            conf_values.append(control.confidence)
            reason = f"{control.control_type} {effect} this exposure; mitigation is discounted by effectiveness and evidence confidence."

        evaluated.append(EvaluatedControl(
            control_id=control.id,
            control_type=control.control_type,
            owner=control.owner,
            effect=effect,
            effectiveness=float(control.effectiveness),
            confidence=float(control.confidence),
            effective_mitigation=round(mitigation*100.0,3),
            evidence=control.evidence or {},
            expired=expired,
            temporary=bool(control.temporary),
            expires_at=control.expires_at,
            mitigation_until=control.mitigation_until,
            reason=reason,
        ))

    raw_residual = inherent_risk * remaining
    floor = inherent_risk * 0.05 if inherent_risk > 0 else 0.0
    residual = round(max(floor, min(100.0, raw_residual)), 2)

    combined_eff = round(sum(eff_values)/len(eff_values),2) if eff_values else 0.0
    combined_conf = round(sum(conf_values)/len(conf_values),2) if conf_values else 0.0

    return ResidualRiskCalculation(
        inherent_risk=round(inherent_risk,2),
        combined_control_effectiveness=combined_eff,
        combined_control_confidence=combined_conf,
        residual_risk=residual,
        controls=evaluated,
        rationale=(
            "Residual risk is derived from inherent risk and evidence-backed control effects. "
            "A compensating control never marks the vulnerability resolved; a residual-risk floor remains."
        ),
    )
