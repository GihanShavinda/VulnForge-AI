from __future__ import annotations

from statistics import mean


def _top_k_refs(rows: list[dict], key, k: int, reverse: bool = True) -> list[str]:
    return [
        row["finding_ref"]
        for row in sorted(rows, key=key, reverse=reverse)[:k]
    ]


def _agreement(candidate: list[str], expert: list[str]) -> float:
    if not expert:
        return 0.0
    return round(len(set(candidate) & set(expert)) / len(expert), 4)


def _precision(rows: list[dict]) -> float:
    predicted = [row for row in rows if row["predicted_applicable"]]
    if not predicted:
        return 0.0
    true_positive = sum(1 for row in predicted if row["applicable"])
    return round(true_positive / len(predicted), 4)


def calculate_evaluation(rows: list[dict], top_k: int = 5) -> tuple[list[dict], dict]:
    if not rows:
        raise ValueError("At least one evaluation finding is required.")

    k = min(top_k, len(rows))
    expert = _top_k_refs(rows, key=lambda r: -r["expert_rank"], k=k)

    cvss = _top_k_refs(rows, key=lambda r: r["cvss_score"], k=k)
    cvss_kev = _top_k_refs(
        rows,
        key=lambda r: (1 if r["kev"] else 0, r["cvss_score"]),
        k=k,
    )
    cvss_kev_epss = _top_k_refs(
        rows,
        key=lambda r: (
            1 if r["kev"] else 0,
            r["epss"],
            r["cvss_score"],
        ),
        k=k,
    )
    environmental = _top_k_refs(
        rows,
        key=lambda r: r["environmental_score"],
        k=k,
    )

    false_positive_count = sum(
        1
        for row in rows
        if row["predicted_applicable"] and not row["applicable"]
    )
    predicted_count = sum(1 for row in rows if row["predicted_applicable"])
    false_positive_rate = (
        false_positive_count / predicted_count
        if predicted_count
        else 0.0
    )

    kev_rows = [row for row in rows if row["kev"]]
    kev_top_environmental = set(environmental)
    kev_prioritisation = (
        sum(1 for row in kev_rows if row["finding_ref"] in kev_top_environmental)
        / len(kev_rows)
        if kev_rows
        else 1.0
    )

    attack_rows = [row for row in rows if row["attack_path_relevant"]]
    attack_path_relevance = (
        sum(1 for row in attack_rows if row["finding_ref"] in kev_top_environmental)
        / len(attack_rows)
        if attack_rows
        else 1.0
    )

    risk_reductions = [
        max(0.0, row["pre_remediation_risk"] - row["post_remediation_risk"])
        for row in rows
    ]

    metrics = {
        "precision_of_applicable_findings": _precision(rows),
        "false_positive_rate": round(false_positive_rate, 4),
        "top_k_priority_agreement": {
            "k": k,
            "cvss_only": _agreement(cvss, expert),
            "cvss_plus_kev": _agreement(cvss_kev, expert),
            "cvss_plus_kev_plus_epss": _agreement(cvss_kev_epss, expert),
            "vulnforge_environmental_risk": _agreement(environmental, expert),
        },
        "kev_prioritisation": round(kev_prioritisation, 4),
        "attack_path_relevance": round(attack_path_relevance, 4),
        "time_to_triage_seconds_mean": round(mean(row["triage_seconds"] for row in rows), 2),
        "risk_reduction_after_remediation_mean": round(mean(risk_reductions), 2),
        "ai_factual_accuracy": round(mean(int(row["ai_factual_correct"]) for row in rows), 4),
        "ai_unsupported_claim_rate": round(mean(int(row["ai_unsupported_claim"]) for row in rows), 4),
        "security_rule_accuracy": round(mean(int(row["security_rule_correct"]) for row in rows), 4),
        "verification_success_rate": round(mean(int(row["verification_success"]) for row in rows), 4),
    }

    ranks = {}
    for method, ranking in {
        "cvss_only": cvss,
        "cvss_plus_kev": cvss_kev,
        "cvss_plus_kev_plus_epss": cvss_kev_epss,
        "vulnforge_environmental_risk": environmental,
        "expert_manual": expert,
    }.items():
        ranks[method] = {ref: idx + 1 for idx, ref in enumerate(ranking)}

    experiment_table = []
    for row in rows:
        experiment_table.append(
            {
                "finding_ref": row["finding_ref"],
                "cvss_score": row["cvss_score"],
                "kev": row["kev"],
                "epss": row["epss"],
                "environmental_score": row["environmental_score"],
                "expert_rank": row["expert_rank"],
                "cvss_only_top_k_rank": ranks["cvss_only"].get(row["finding_ref"]),
                "cvss_kev_top_k_rank": ranks["cvss_plus_kev"].get(row["finding_ref"]),
                "cvss_kev_epss_top_k_rank": ranks["cvss_plus_kev_plus_epss"].get(row["finding_ref"]),
                "environmental_top_k_rank": ranks["vulnforge_environmental_risk"].get(row["finding_ref"]),
                "applicable": row["applicable"],
                "predicted_applicable": row["predicted_applicable"],
                "attack_path_relevant": row["attack_path_relevant"],
                "risk_reduction": round(
                    row["pre_remediation_risk"] - row["post_remediation_risk"],
                    2,
                ),
            }
        )

    return experiment_table, metrics
