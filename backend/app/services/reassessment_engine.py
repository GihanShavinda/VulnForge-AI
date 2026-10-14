from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReassessmentComparison:
    risk_delta: float
    attack_path_change: str
    control_change: dict
    verification_success: bool
    regression_detected: bool
    regression_reasons: list[str]


def _path_signature(value: dict) -> tuple:
    nodes = value.get("nodes") or value.get("node_sequence") or []
    relationships = value.get("relationships") or value.get("relationship_sequence") or []
    status = value.get("status") or value.get("path_status")
    return tuple(nodes), tuple(relationships), status


def _control_ids(controls: list[dict]) -> set[str]:
    result = set()
    for control in controls:
        value = (
            control.get("id")
            or control.get("control_id")
            or control.get("name")
            or control.get("control_type")
        )
        if value is not None:
            result.add(str(value))
    return result


def compare_reassessment(
    *,
    before_score: float,
    after_score: float,
    before_evidence: dict,
    after_evidence: dict,
    before_attack_path: dict,
    after_attack_path: dict,
    before_controls: list[dict],
    after_controls: list[dict],
) -> ReassessmentComparison:
    risk_delta = round(before_score - after_score, 2)

    before_path = _path_signature(before_attack_path)
    after_path = _path_signature(after_attack_path)

    if before_path == after_path:
        attack_path_change = "unchanged"
    elif before_path != ((), (), None) and after_path == ((), (), None):
        attack_path_change = "removed"
    elif before_path == ((), (), None) and after_path != ((), (), None):
        attack_path_change = "introduced"
    else:
        attack_path_change = "changed"

    before_control_ids = _control_ids(before_controls)
    after_control_ids = _control_ids(after_controls)
    control_change = {
        "added": sorted(after_control_ids - before_control_ids),
        "removed": sorted(before_control_ids - after_control_ids),
        "unchanged": sorted(before_control_ids & after_control_ids),
    }

    regression_reasons: list[str] = []

    if after_score > before_score:
        regression_reasons.append("risk_score_increased")

    if attack_path_change == "introduced":
        regression_reasons.append("new_attack_path_introduced")

    if control_change["removed"]:
        regression_reasons.append("security_control_removed")

    before_state = before_evidence.get("state")
    after_state = after_evidence.get("state")
    if before_state == "remediated" and after_state not in {"remediated", "not_applicable"}:
        regression_reasons.append("remediation_state_regressed")

    regression_detected = bool(regression_reasons)

    evidence_improved = after_evidence != before_evidence
    verification_success = (
        not regression_detected
        and after_score <= before_score
        and (
            after_score < before_score
            or attack_path_change in {"removed", "changed"}
            or bool(control_change["added"])
            or evidence_improved
        )
    )

    return ReassessmentComparison(
        risk_delta=risk_delta,
        attack_path_change=attack_path_change,
        control_change=control_change,
        verification_success=verification_success,
        regression_detected=regression_detected,
        regression_reasons=regression_reasons,
    )
