from __future__ import annotations

from app.schemas.attack_graph import NODE_LABELS, RELATIONSHIP_TYPES, SCENARIOS


def validate_scenario(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in SCENARIOS:
        raise ValueError(
            f"Unsupported scenario: {value}. Allowed values: {', '.join(SCENARIOS)}"
        )
    return normalized


def validate_node_label(value: str) -> str:
    if value not in NODE_LABELS:
        raise ValueError(
            f"Unsupported node label: {value}. Allowed values: {', '.join(NODE_LABELS)}"
        )
    return value


def validate_relationship_type(value: str) -> str:
    if value not in RELATIONSHIP_TYPES:
        raise ValueError(
            f"Unsupported relationship type: {value}. Allowed values: {', '.join(RELATIONSHIP_TYPES)}"
        )
    return value
