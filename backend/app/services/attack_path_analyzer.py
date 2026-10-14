from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


CONFIDENCE_SCORE = {
    "confirmed": 1.0,
    "high confidence": 0.85,
    "medium confidence": 0.65,
    "low confidence": 0.4,
    "unknown": 0.2,
}

STATUS_SCORE = {
    "confirmed": 1.0,
    "supported": 0.75,
    "theoretical": 0.4,
    "unknown": 0.2,
}


@dataclass(frozen=True)
class PathAnalysis:
    path_length: int
    entry_point_exposure: str
    weakest_control: str | None
    critical_destination: bool
    enabling_findings: int
    credential_dependency: bool
    privilege_increase: bool
    reachable_high_value_asset: bool
    path_status: str
    confidence: str
    confidence_score: float
    evidence: list[dict]
    node_sequence: list[str]
    relationship_sequence: list[str]
    rationale: str


def _confidence_label(
    score: float,
) -> str:
    if score >= 0.9:
        return "confirmed"

    if score >= 0.75:
        return "high confidence"

    if score >= 0.55:
        return "medium confidence"

    if score >= 0.35:
        return "low confidence"

    return "unknown"


def _node_labels(
    node: dict[str, Any],
) -> set[str]:
    return set(
        node.get("labels")
        or []
    )


def _node_props(
    node: dict[str, Any],
) -> dict[str, Any]:
    return (
        node.get("properties")
        or {}
    )


def _relationship_details(
    properties: dict[str, Any],
) -> dict[str, Any]:
    """
    Recover structured edge evidence.

    V16 stores structured Neo4j relationship evidence as JSON because native
    Neo4j relationship properties cannot contain maps.
    """

    raw = properties.get(
        "details_json"
    )

    if raw is None:
        # Backward compatibility for unit tests or in-memory path structures
        # that still supply `details` directly.
        value = properties.get(
            "details"
        )

        if isinstance(
            value,
            dict,
        ):
            return value

        return {}

    if isinstance(
        raw,
        dict,
    ):
        return raw

    if not isinstance(
        raw,
        str,
    ):
        return {}

    try:
        parsed = json.loads(
            raw
        )
    except (
        json.JSONDecodeError,
        TypeError,
    ):
        return {}

    if isinstance(
        parsed,
        dict,
    ):
        return parsed

    return {}


def analyze_path(
    raw_path: dict[str, Any],
) -> PathAnalysis:
    nodes = (
        raw_path.get("nodes")
        or []
    )

    relationships = (
        raw_path.get(
            "relationships"
        )
        or []
    )

    node_sequence = [
        str(
            node.get("key")
            or ""
        )
        for node in nodes
    ]

    relationship_sequence = [
        str(
            rel.get(
                "relationship_type"
            )
            or ""
        )
        for rel in relationships
    ]

    edge_evidence: list[dict] = []

    status_scores: list[float] = []
    confidence_scores: list[float] = []

    weakest_control = None
    enabling_findings = 0
    credential_dependency = False
    privilege_increase = False

    for index, rel in enumerate(
        relationships
    ):
        props = (
            rel.get("properties")
            or {}
        )

        evidence_status = str(
            props.get(
                "evidence_status"
            )
            or "theoretical"
        ).lower()

        confidence = str(
            props.get(
                "confidence"
            )
            or "unknown"
        ).lower()

        status_scores.append(
            STATUS_SCORE.get(
                evidence_status,
                0.2,
            )
        )

        confidence_scores.append(
            CONFIDENCE_SCORE.get(
                confidence,
                0.2,
            )
        )

        source_key = (
            node_sequence[index]
            if index
            < len(node_sequence)
            else ""
        )

        target_key = (
            node_sequence[index + 1]
            if index + 1
            < len(node_sequence)
            else ""
        )

        details = (
            _relationship_details(
                props
            )
        )

        edge_evidence.append(
            {
                "edge_index": index,
                "relationship_type": (
                    rel.get(
                        "relationship_type"
                    )
                ),
                "source_node_key": (
                    source_key
                ),
                "target_node_key": (
                    target_key
                ),
                "evidence_status": (
                    evidence_status
                ),
                "confidence": (
                    confidence
                ),
                "source": props.get(
                    "source",
                    "graph evidence",
                ),
                "details": details,
            }
        )

        relationship_type = (
            rel.get(
                "relationship_type"
            )
        )

        if relationship_type in {
            "HAS_VULNERABILITY",
            "ENABLES",
            "AFFECTS",
        }:
            enabling_findings += 1

        if relationship_type in {
            "HAS_CREDENTIAL",
            "AUTHENTICATES_TO",
            "USES_ACCOUNT",
        }:
            credential_dependency = True

        if (
            bool(
                props.get(
                    "privilege_increase"
                )
            )
            or bool(
                details.get(
                    "privilege_increase"
                )
            )
        ):
            privilege_increase = True

    for node in nodes:
        labels = _node_labels(
            node
        )

        props = _node_props(
            node
        )

        if "SecurityControl" in labels:
            strength = str(
                props.get(
                    "strength"
                )
                or props.get(
                    "effectiveness"
                )
                or ""
            )

            if weakest_control is None:
                weakest_control = str(
                    node.get("name")
                    or node.get("key")
                    or ""
                )

            if strength.lower() in {
                "weak",
                "low",
                "partial",
                "degraded",
            }:
                weakest_control = str(
                    node.get("name")
                    or node.get("key")
                    or ""
                )

        if labels.intersection(
            {
                "Vulnerability",
                "ConfigFinding",
                "SecretFinding",
            }
        ):
            enabling_findings += 1

        if labels.intersection(
            {
                "Credential",
                "Account",
            }
        ):
            credential_dependency = True

        if bool(
            props.get(
                "privilege_increase"
            )
        ):
            privilege_increase = True

    first_node = (
        nodes[0]
        if nodes
        else {}
    )

    first_props = _node_props(
        first_node
    )

    entry_point_exposure = str(
        first_props.get(
            "exposure"
        )
        or first_props.get(
            "entry_point_exposure"
        )
        or "unknown"
    )

    destination = (
        nodes[-1]
        if nodes
        else {}
    )

    destination_labels = (
        _node_labels(
            destination
        )
    )

    destination_props = (
        _node_props(
            destination
        )
    )

    critical_destination = bool(
        "SensitiveAsset"
        in destination_labels
        or destination_props.get(
            "critical"
        )
        is True
        or destination_props.get(
            "criticality"
        )
        in {
            "critical",
            "high",
        }
    )

    reachable_high_value_asset = bool(
        critical_destination
        or destination_props.get(
            "high_value"
        )
        is True
    )

    any_theoretical = any(
        item[
            "evidence_status"
        ]
        != "confirmed"
        for item
        in edge_evidence
    )

    if not relationships:
        path_status = "theoretical"
        score = 0.2

    else:
        combined_scores = [
            min(
                status_scores[i],
                confidence_scores[i],
            )
            for i
            in range(
                len(status_scores)
            )
        ]

        score = (
            sum(
                combined_scores
            )
            / len(
                combined_scores
            )
        )

        path_status = (
            "theoretical"
            if any_theoretical
            else "evidence-confirmed"
        )

    confidence = (
        _confidence_label(
            score
        )
    )

    if (
        path_status
        == "evidence-confirmed"
    ):
        rationale = (
            "Every path edge is supported "
            "by confirmed graph evidence. "
            "This confirms the relationship "
            "chain only; it does not confirm "
            "exploitation or compromise."
        )

    else:
        rationale = (
            "One or more graph edges are "
            "supported only by partial, "
            "theoretical, or unknown evidence. "
            "The path is therefore theoretical, "
            "does not confirm exploitation, "
            "and must not be interpreted as "
            "exploit success."
        )

    return PathAnalysis(
        path_length=len(
            relationships
        ),
        entry_point_exposure=(
            entry_point_exposure
        ),
        weakest_control=(
            weakest_control
        ),
        critical_destination=(
            critical_destination
        ),
        enabling_findings=(
            enabling_findings
        ),
        credential_dependency=(
            credential_dependency
        ),
        privilege_increase=(
            privilege_increase
        ),
        reachable_high_value_asset=(
            reachable_high_value_asset
        ),
        path_status=(
            path_status
        ),
        confidence=(
            confidence
        ),
        confidence_score=round(
            score,
            3,
        ),
        evidence=edge_evidence,
        node_sequence=node_sequence,
        relationship_sequence=(
            relationship_sequence
        ),
        rationale=rationale,
    )