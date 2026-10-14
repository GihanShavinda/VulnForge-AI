from dataclasses import dataclass
from datetime import date, timedelta
from uuid import uuid4
from app.services.security_control_risk import calculate_residual_risk

@dataclass
class Control:
    id: object
    control_type: str
    owner: str
    effectiveness: float
    confidence: float
    evidence: dict
    temporary: bool=False
    effective_from: date|None=None
    expires_at: date|None=None
    mitigation_until: date|None=None
    enabled: bool=True

def c(control_type, effectiveness, confidence, **kwargs):
    return Control(uuid4(), control_type, "Security Team", effectiveness, confidence, {"source":"lab evidence"}, **kwargs)

def test_same_vulnerability_same_criticality_different_controls_different_residual_risk():
    inherent = 80.0
    weak = calculate_residual_risk(
        inherent_risk=inherent,
        exposure_type="web_application",
        controls=[c("edr_av", 60, 80)],
    )
    strong = calculate_residual_risk(
        inherent_risk=inherent,
        exposure_type="web_application",
        controls=[c("waf", 90, 95), c("reverse_proxy", 80, 90)],
    )
    assert weak.inherent_risk == strong.inherent_risk == 80.0
    assert strong.residual_risk < weak.residual_risk

def test_compensating_control_never_marks_vulnerability_resolved():
    result = calculate_residual_risk(
        inherent_risk=100.0,
        exposure_type="network_service",
        controls=[c("service_disabled", 100, 100)],
    )
    assert result.residual_risk == 10.0  # per-control mitigation capped at 90%
    assert result.residual_risk > 0

def test_expired_temporary_control_has_no_mitigation():
    result = calculate_residual_risk(
        inherent_risk=70.0,
        exposure_type="web_application",
        controls=[c("waf", 100, 100, temporary=True, mitigation_until=date.today()-timedelta(days=1))],
    )
    assert result.residual_risk == 70.0
    assert result.controls[0].expired is True
    assert result.controls[0].effective_mitigation == 0.0

def test_control_confidence_changes_residual_risk():
    low_conf = calculate_residual_risk(
        inherent_risk=80.0,
        exposure_type="web_application",
        controls=[c("waf", 90, 30)],
    )
    high_conf = calculate_residual_risk(
        inherent_risk=80.0,
        exposure_type="web_application",
        controls=[c("waf", 90, 95)],
    )
    assert high_conf.residual_risk < low_conf.residual_risk
