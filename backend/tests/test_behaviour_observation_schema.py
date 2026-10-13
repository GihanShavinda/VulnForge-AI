import pytest
from pydantic import ValidationError

from app.schemas.weakness_context import BehaviourObservationCreate


def test_observed_behaviour_requires_evidence():
    with pytest.raises(ValidationError):
        BehaviourObservationCreate(
            finding_id="finding-1",
            canonical_id="CVE-2026-0001",
            attack_id="T1190",
            context_type="observed",
            mapping_confidence="high confidence",
            mapping_source="lab telemetry",
            mapping_rationale="Observed exploit-like request pattern.",
            evidence={},
        )


def test_potential_state_cannot_be_posted_as_observed_evidence():
    with pytest.raises(ValidationError):
        BehaviourObservationCreate(
            finding_id="finding-1",
            attack_id="T1190",
            context_type="potential",
            mapping_source="test",
            mapping_rationale="test",
            evidence={"event": "x"},
        )


def test_confirmed_behaviour_accepts_explicit_evidence():
    item = BehaviourObservationCreate(
        finding_id="finding-1",
        canonical_id="CVE-2026-0001",
        attack_id="T1190",
        context_type="confirmed",
        mapping_confidence="confirmed",
        mapping_source="correlated lab evidence",
        mapping_rationale="Exploit request and post-exploit process were both observed.",
        evidence={"request_id": "abc", "process_event_id": "def"},
    )
    assert item.context_type == "confirmed"
