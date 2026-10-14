from __future__ import annotations

from app.schemas.grounded_analyst import (
    GroundedAnalystOutput,
    StructuredEvidence,
    UNTRUSTED_TEXT_TYPES,
)


class GroundingViolation(ValueError):
    pass


def trusted_claim_evidence(evidence: list[StructuredEvidence]) -> list[StructuredEvidence]:
    return [
        item for item in evidence
        if item.evidence_type not in UNTRUSTED_TEXT_TYPES
    ]


def untrusted_evidence(evidence: list[StructuredEvidence]) -> list[StructuredEvidence]:
    return [
        item for item in evidence
        if item.evidence_type in UNTRUSTED_TEXT_TYPES
    ]


def validate_output_grounding(
    output: GroundedAnalystOutput,
    evidence: list[StructuredEvidence],
) -> None:
    allowed = {item.evidence_id for item in evidence}
    statements = [
        output.executive_summary,
        output.technical_summary,
        output.exploitability,
        output.attack_path_effect,
        output.business_impact,
        output.confidence,
        *output.recommended_actions,
        *output.verification_steps,
        *output.unknowns,
    ]

    for statement in statements:
        if not statement.evidence_ids:
            raise GroundingViolation(
                "Every statement must reference at least one evidence identifier."
            )
        unknown = set(statement.evidence_ids) - allowed
        if unknown:
            raise GroundingViolation(
                "Output references evidence identifiers not supplied in the request: "
                + ", ".join(sorted(unknown))
            )

    output_evidence_ids = {item.evidence_id for item in output.evidence}
    if not output_evidence_ids.issubset(allowed):
        raise GroundingViolation(
            "Output evidence list contains identifiers not supplied in the request."
        )
