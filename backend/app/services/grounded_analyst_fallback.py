from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.schemas.grounded_analyst import (
    EvidenceBackedStatement,
    EvidenceView,
    GroundedAnalystOutput,
    StructuredEvidence,
)
from app.services.grounding_policy import trusted_claim_evidence, untrusted_evidence


def _by_type(evidence: list[StructuredEvidence]) -> dict[str, list[StructuredEvidence]]:
    result: dict[str, list[StructuredEvidence]] = defaultdict(list)
    for item in evidence:
        result[item.evidence_type].append(item)
    return result


def _ids(items: list[StructuredEvidence]) -> list[str]:
    return [item.evidence_id for item in items]


def _fallback_reference(
    trusted: list[StructuredEvidence],
    all_evidence: list[StructuredEvidence],
) -> list[str]:
    if trusted:
        return [trusted[0].evidence_id]
    return [all_evidence[0].evidence_id]


def _first_value(
    items: list[StructuredEvidence],
    *keys: str,
) -> tuple[Any | None, list[str]]:
    for item in items:
        for key in keys:
            value = item.data.get(key)
            if value not in (None, "", []):
                return value, [item.evidence_id]
    return None, []


def deterministic_analysis(
    evidence: list[StructuredEvidence],
) -> GroundedAnalystOutput:
    trusted = trusted_claim_evidence(evidence)
    untrusted = untrusted_evidence(evidence)
    by_type = _by_type(trusted)
    fallback_ids = _fallback_reference(trusted, evidence)

    asset, asset_ids = _first_value(by_type.get("asset", []), "name", "hostname", "ip", "asset_id")
    service, service_ids = _first_value(by_type.get("service", []), "name", "service", "port")
    version, version_ids = _first_value(by_type.get("confirmed_version", []), "version")
    cve, cve_ids = _first_value(by_type.get("cve", []), "cve_id")
    cvss, cvss_ids = _first_value(by_type.get("cvss", []), "score", "base_score")
    epss, epss_ids = _first_value(by_type.get("epss", []), "probability", "score")
    kev, kev_ids = _first_value(by_type.get("kev", []), "known_exploited", "listed")
    reachability, reachability_ids = _first_value(by_type.get("reachability", []), "state", "reachable")
    patch, patch_ids = _first_value(by_type.get("patch_information", []), "status", "patch_status")
    attack_path, attack_path_ids = _first_value(by_type.get("attack_path", []), "summary", "path", "status")

    controls = by_type.get("security_control", [])
    config = by_type.get("configuration_state", [])
    business = by_type.get("business_context", [])
    confidence_items = by_type.get("evidence_confidence", [])

    summary_parts: list[str] = []
    summary_ids: list[str] = []
    if asset is not None:
        summary_parts.append(f"Asset: {asset}.")
        summary_ids += asset_ids
    if cve is not None:
        summary_parts.append(f"Structured CVE evidence identifies {cve}.")
        summary_ids += cve_ids
    if service is not None:
        summary_parts.append(f"Observed service: {service}.")
        summary_ids += service_ids
    if not summary_parts:
        summary_parts = ["insufficient evidence"]
        summary_ids = fallback_ids

    technical_parts: list[str] = []
    technical_ids: list[str] = []
    if version is not None:
        technical_parts.append(f"Confirmed version: {version}.")
        technical_ids += version_ids
    if cvss is not None:
        technical_parts.append(f"CVSS evidence reports {cvss}.")
        technical_ids += cvss_ids
    if config:
        technical_parts.append("Structured configuration-state evidence is present.")
        technical_ids += _ids(config)
    if controls:
        technical_parts.append("Structured security-control evidence is present.")
        technical_ids += _ids(controls)
    if not technical_parts:
        technical_parts = ["insufficient evidence"]
        technical_ids = fallback_ids

    exploit_parts: list[str] = []
    exploit_ids: list[str] = []
    if kev is not None:
        exploit_parts.append(
            "Known exploitation evidence is present."
            if bool(kev)
            else "Known exploitation is not asserted by the supplied KEV evidence."
        )
        exploit_ids += kev_ids
    if epss is not None:
        exploit_parts.append(f"EPSS evidence reports {epss}.")
        exploit_ids += epss_ids
    if reachability is not None:
        exploit_parts.append(f"Reachability evidence reports {reachability}.")
        exploit_ids += reachability_ids
    if not exploit_parts:
        exploit_parts = ["insufficient evidence"]
        exploit_ids = fallback_ids

    attack_path_statement = (
        EvidenceBackedStatement(
            text=f"Attack-path evidence reports: {attack_path}.",
            evidence_ids=attack_path_ids,
        )
        if attack_path is not None
        else EvidenceBackedStatement(
            text="insufficient evidence",
            evidence_ids=fallback_ids,
        )
    )

    if business:
        business_value, business_ids = _first_value(
            business,
            "impact",
            "criticality",
            "description",
        )
        business_statement = EvidenceBackedStatement(
            text=(
                f"Business context: {business_value}."
                if business_value is not None
                else "Structured business-context evidence is present."
            ),
            evidence_ids=business_ids or _ids(business),
        )
    else:
        business_statement = EvidenceBackedStatement(
            text="insufficient evidence",
            evidence_ids=fallback_ids,
        )

    actions = []
    if patch is not None:
        actions.append(
            EvidenceBackedStatement(
                text=f"Validate and follow the supplied patch state: {patch}.",
                evidence_ids=patch_ids,
            )
        )
    else:
        actions.append(
            EvidenceBackedStatement(
                text="Patch recommendation: insufficient evidence",
                evidence_ids=cve_ids or version_ids or fallback_ids,
            )
        )

    if controls:
        actions.append(
            EvidenceBackedStatement(
                text=(
                    "Review the documented security controls and verify their current "
                    "effectiveness before changing residual-risk status."
                ),
                evidence_ids=_ids(controls),
            )
        )

    verification_steps = []
    if version is not None:
        verification_steps.append(
            EvidenceBackedStatement(
                text="Re-verify the confirmed software or service version using the same evidence source class.",
                evidence_ids=version_ids,
            )
        )
    if reachability is not None:
        verification_steps.append(
            EvidenceBackedStatement(
                text="Re-validate reachability within the authorized lab scope.",
                evidence_ids=reachability_ids,
            )
        )
    if patch is not None:
        verification_steps.append(
            EvidenceBackedStatement(
                text="Verify patch state from an authoritative structured source before closing the finding.",
                evidence_ids=patch_ids,
            )
        )
    if not verification_steps:
        verification_steps.append(
            EvidenceBackedStatement(
                text="Verification plan: insufficient evidence",
                evidence_ids=fallback_ids,
            )
        )

    confidence_text = "insufficient evidence"
    confidence_ids = fallback_ids
    if confidence_items:
        confidence_value, confidence_value_ids = _first_value(
            confidence_items,
            "level",
            "confidence",
        )
        if confidence_value is not None:
            confidence_text = f"Evidence confidence: {confidence_value}."
            confidence_ids = confidence_value_ids
    else:
        explicit = [
            item
            for item in trusted
            if item.confidence in {"confirmed", "high", "medium", "low"}
        ]
        if explicit:
            levels = [item.confidence for item in explicit]
            confidence_text = (
                "Evidence confidence levels supplied: "
                + ", ".join(sorted(set(levels)))
                + "."
            )
            confidence_ids = _ids(explicit)

    unknowns = []
    required_checks = [
        ("confirmed affected version", version, cve_ids or fallback_ids),
        ("patch status", patch, cve_ids or fallback_ids),
        ("attack path", attack_path, cve_ids or fallback_ids),
        ("business impact", business[0] if business else None, asset_ids or fallback_ids),
    ]
    for name, value, ids in required_checks:
        if value is None:
            unknowns.append(
                EvidenceBackedStatement(
                    text=f"{name}: insufficient evidence",
                    evidence_ids=ids,
                )
            )

    if untrusted:
        unknowns.append(
            EvidenceBackedStatement(
                text=(
                    "Untrusted imported narrative was retained as data and was not used "
                    "to create structured security claims."
                ),
                evidence_ids=_ids(untrusted),
            )
        )

    return GroundedAnalystOutput(
        executive_summary=EvidenceBackedStatement(
            text=" ".join(summary_parts),
            evidence_ids=list(dict.fromkeys(summary_ids)),
        ),
        technical_summary=EvidenceBackedStatement(
            text=" ".join(technical_parts),
            evidence_ids=list(dict.fromkeys(technical_ids)),
        ),
        exploitability=EvidenceBackedStatement(
            text=" ".join(exploit_parts),
            evidence_ids=list(dict.fromkeys(exploit_ids)),
        ),
        evidence=[
            EvidenceView(
                evidence_id=item.evidence_id,
                evidence_type=item.evidence_type,
                source=item.source,
                confidence=item.confidence,
            )
            for item in evidence
        ],
        attack_path_effect=attack_path_statement,
        business_impact=business_statement,
        recommended_actions=actions,
        verification_steps=verification_steps,
        confidence=EvidenceBackedStatement(
            text=confidence_text,
            evidence_ids=confidence_ids,
        ),
        unknowns=unknowns,
    )
