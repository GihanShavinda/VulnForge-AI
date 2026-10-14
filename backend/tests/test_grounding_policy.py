import pytest

from app.schemas.grounded_analyst import (
    EvidenceBackedStatement,
    EvidenceView,
    GroundedAnalystOutput,
    StructuredEvidence,
)
from app.services.grounding_policy import GroundingViolation, validate_output_grounding


def test_rejects_output_referencing_invented_evidence_id():
    evidence = [
        StructuredEvidence(
            evidence_id="E1",
            evidence_type="asset",
            source="lab",
            confidence="confirmed",
            data={"name": "server"},
        )
    ]
    output = GroundedAnalystOutput(
        executive_summary=EvidenceBackedStatement(text="x", evidence_ids=["E999"]),
        technical_summary=EvidenceBackedStatement(text="x", evidence_ids=["E1"]),
        exploitability=EvidenceBackedStatement(text="x", evidence_ids=["E1"]),
        evidence=[
            EvidenceView(
                evidence_id="E1",
                evidence_type="asset",
                source="lab",
                confidence="confirmed",
            )
        ],
        attack_path_effect=EvidenceBackedStatement(text="x", evidence_ids=["E1"]),
        business_impact=EvidenceBackedStatement(text="x", evidence_ids=["E1"]),
        recommended_actions=[EvidenceBackedStatement(text="x", evidence_ids=["E1"])],
        verification_steps=[EvidenceBackedStatement(text="x", evidence_ids=["E1"])],
        confidence=EvidenceBackedStatement(text="x", evidence_ids=["E1"]),
        unknowns=[],
    )

    with pytest.raises(GroundingViolation):
        validate_output_grounding(output, evidence)
