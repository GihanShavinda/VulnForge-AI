from __future__ import annotations

from datetime import datetime, timezone

from app.schemas.remediation import ALTERNATIVE_STATES, PRIMARY_FLOW


ALLOWED_TRANSITIONS = {
    "Open": {"Triaged", *ALTERNATIVE_STATES},
    "Triaged": {"Assigned", *ALTERNATIVE_STATES},
    "Assigned": {"Remediation In Progress", *ALTERNATIVE_STATES},
    "Remediation In Progress": {"Ready for Verification", *ALTERNATIVE_STATES},
    "Ready for Verification": {"Verified", "Remediation In Progress", *ALTERNATIVE_STATES},
    "Verified": {"Closed", "Remediation In Progress", *ALTERNATIVE_STATES},
    "Closed": set(),
    "Accepted Risk": {"Open"},
    "False Positive": {"Open"},
    "Deferred": {"Open"},
}


def validate_transition(
    current_status: str,
    new_status: str,
    *,
    has_closure_evidence: bool,
    has_successful_reassessment: bool,
) -> None:
    allowed = ALLOWED_TRANSITIONS.get(current_status, set())

    if new_status not in allowed:
        raise ValueError(
            f"Invalid remediation transition: {current_status} -> {new_status}."
        )

    if new_status == "Verified" and not has_successful_reassessment:
        raise ValueError(
            "A successful post-remediation reassessment is required before Verified."
        )

    if new_status == "Closed":
        if not has_closure_evidence:
            raise ValueError("Closure evidence is required before Closed.")
        if not has_successful_reassessment:
            raise ValueError(
                "A successful post-remediation reassessment is required before Closed."
            )


def apply_alternative_reason(case, new_status: str, reason: str | None) -> None:
    if new_status == "Accepted Risk":
        case.risk_acceptance_reason = reason
    elif new_status == "False Positive":
        case.false_positive_reason = reason
    elif new_status == "Deferred":
        case.deferral_reason = reason


def mark_closed(case) -> None:
    case.closed_at = datetime.now(timezone.utc)
