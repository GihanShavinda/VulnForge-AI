from app.services.reassessment_engine import compare_reassessment


def test_successful_remediation_reduces_risk_and_removes_attack_path():
    result = compare_reassessment(
        before_score=82,
        after_score=28,
        before_evidence={"state": "vulnerable"},
        after_evidence={"state": "remediated"},
        before_attack_path={
            "nodes": ["attacker", "web", "db"],
            "relationships": ["REACHABLE_FROM", "CAN_ACCESS"],
            "status": "theoretical",
        },
        after_attack_path={},
        before_controls=[{"name": "host firewall"}],
        after_controls=[
            {"name": "host firewall"},
            {"name": "WAF"},
        ],
    )

    assert result.risk_delta == 54
    assert result.attack_path_change == "removed"
    assert result.control_change["added"] == ["WAF"]
    assert result.verification_success is True
    assert result.regression_detected is False


def test_regression_detects_increased_risk_new_path_and_removed_control():
    result = compare_reassessment(
        before_score=25,
        after_score=70,
        before_evidence={"state": "remediated"},
        after_evidence={"state": "vulnerable"},
        before_attack_path={},
        after_attack_path={
            "nodes": ["attacker", "host"],
            "relationships": ["REACHABLE_FROM"],
            "status": "theoretical",
        },
        before_controls=[{"name": "WAF"}],
        after_controls=[],
    )

    assert result.regression_detected is True
    assert "risk_score_increased" in result.regression_reasons
    assert "new_attack_path_introduced" in result.regression_reasons
    assert "security_control_removed" in result.regression_reasons
    assert "remediation_state_regressed" in result.regression_reasons
    assert result.verification_success is False
