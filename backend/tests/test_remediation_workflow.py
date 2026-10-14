import pytest

from app.services.remediation_workflow import validate_transition


def test_primary_workflow_allows_expected_transition():
    validate_transition(
        "Open",
        "Triaged",
        has_closure_evidence=False,
        has_successful_reassessment=False,
    )


def test_verified_requires_successful_reassessment():
    with pytest.raises(ValueError):
        validate_transition(
            "Ready for Verification",
            "Verified",
            has_closure_evidence=True,
            has_successful_reassessment=False,
        )


def test_closed_requires_evidence_and_successful_reassessment():
    with pytest.raises(ValueError):
        validate_transition(
            "Verified",
            "Closed",
            has_closure_evidence=False,
            has_successful_reassessment=True,
        )

    with pytest.raises(ValueError):
        validate_transition(
            "Verified",
            "Closed",
            has_closure_evidence=True,
            has_successful_reassessment=False,
        )

    validate_transition(
        "Verified",
        "Closed",
        has_closure_evidence=True,
        has_successful_reassessment=True,
    )


def test_alternative_state_is_available():
    validate_transition(
        "Open",
        "Accepted Risk",
        has_closure_evidence=False,
        has_successful_reassessment=False,
    )
