from app.services.evaluation_engine import calculate_evaluation


def rows():
    return [
        {
            "finding_ref": "F1",
            "cvss_score": 10.0,
            "kev": False,
            "epss": 0.05,
            "environmental_score": 35.0,
            "expert_rank": 4,
            "predicted_applicable": True,
            "applicable": True,
            "attack_path_relevant": False,
            "triage_seconds": 100,
            "pre_remediation_risk": 35,
            "post_remediation_risk": 20,
            "ai_factual_correct": True,
            "ai_unsupported_claim": False,
            "security_rule_correct": True,
            "verification_success": True,
        },
        {
            "finding_ref": "F2",
            "cvss_score": 6.5,
            "kev": True,
            "epss": 0.92,
            "environmental_score": 94.0,
            "expert_rank": 1,
            "predicted_applicable": True,
            "applicable": True,
            "attack_path_relevant": True,
            "triage_seconds": 50,
            "pre_remediation_risk": 94,
            "post_remediation_risk": 30,
            "ai_factual_correct": True,
            "ai_unsupported_claim": False,
            "security_rule_correct": True,
            "verification_success": True,
        },
        {
            "finding_ref": "F3",
            "cvss_score": 8.0,
            "kev": False,
            "epss": 0.30,
            "environmental_score": 60.0,
            "expert_rank": 2,
            "predicted_applicable": True,
            "applicable": False,
            "attack_path_relevant": True,
            "triage_seconds": 70,
            "pre_remediation_risk": 60,
            "post_remediation_risk": 55,
            "ai_factual_correct": False,
            "ai_unsupported_claim": True,
            "security_rule_correct": False,
            "verification_success": False,
        },
        {
            "finding_ref": "F4",
            "cvss_score": 5.0,
            "kev": False,
            "epss": 0.10,
            "environmental_score": 50.0,
            "expert_rank": 3,
            "predicted_applicable": False,
            "applicable": False,
            "attack_path_relevant": False,
            "triage_seconds": 80,
            "pre_remediation_risk": 50,
            "post_remediation_risk": 40,
            "ai_factual_correct": True,
            "ai_unsupported_claim": False,
            "security_rule_correct": True,
            "verification_success": True,
        },
    ]


def test_final_experiment_table_and_required_metrics():
    table, metrics = calculate_evaluation(rows(), top_k=2)

    assert len(table) == 4
    assert "precision_of_applicable_findings" in metrics
    assert "false_positive_rate" in metrics
    assert "top_k_priority_agreement" in metrics
    assert "kev_prioritisation" in metrics
    assert "attack_path_relevance" in metrics
    assert "time_to_triage_seconds_mean" in metrics
    assert "risk_reduction_after_remediation_mean" in metrics
    assert "ai_factual_accuracy" in metrics
    assert "ai_unsupported_claim_rate" in metrics
    assert "security_rule_accuracy" in metrics
    assert "verification_success_rate" in metrics


def test_environmental_ranking_can_prioritize_medium_cvss_kev_case():
    table, metrics = calculate_evaluation(rows(), top_k=1)
    top = {
        row["finding_ref"]: row["environmental_top_k_rank"]
        for row in table
    }
    assert top["F2"] == 1
    assert metrics["top_k_priority_agreement"]["vulnforge_environmental_risk"] == 1.0
