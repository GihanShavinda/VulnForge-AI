from __future__ import annotations

import json
from datetime import date, datetime, time
from typing import Any

from app.core.config import get_settings
from app.services.attack_graph_validation import (
    validate_node_label,
    validate_relationship_type,
)


def _neo4j_safe_value(value: Any) -> Any:
    """
    Convert arbitrary VulnForge metadata into Neo4j-safe property values.

    Neo4j node/relationship properties may contain primitives or arrays of
    primitives, but they cannot directly contain nested dictionaries/maps.

    Nested structures are therefore serialized to deterministic JSON.
    """

    if value is None:
        return None

    if isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ):
        return value

    if isinstance(
        value,
        (
            datetime,
            date,
            time,
        ),
    ):
        return value.isoformat()

    if isinstance(value, list):
        # Neo4j supports lists only when their contents are property-safe
        # primitive values. If anything complex appears, preserve the whole
        # structure as JSON instead.
        primitive_items = all(
            item is None
            or isinstance(
                item,
                (
                    str,
                    int,
                    float,
                    bool,
                ),
            )
            for item in value
        )

        if primitive_items:
            # Neo4j property arrays cannot safely contain null entries.
            return [
                item
                for item in value
                if item is not None
            ]

        return json.dumps(
            value,
            sort_keys=True,
            default=str,
        )

    if isinstance(value, dict):
        return json.dumps(
            value,
            sort_keys=True,
            default=str,
        )

    return str(value)


def _neo4j_safe_properties(
    properties: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert a VulnForge metadata dictionary into Neo4j-safe properties.

    None values are omitted rather than persisted.
    """

    result: dict[str, Any] = {}

    for key, value in properties.items():
        safe_value = _neo4j_safe_value(
            value
        )

        if safe_value is None:
            continue

        result[str(key)] = safe_value

    return result


class Neo4jAttackGraph:
    """
    Native Neo4j adapter for VulnForge.

    This component stores evidence relationships only.

    It does not:
    - execute exploits
    - replay credentials
    - perform lateral movement
    - verify attack paths offensively
    """

    def __init__(self):
        settings = get_settings()

        try:
            from neo4j import GraphDatabase
        except ImportError as exc:
            raise RuntimeError(
                "Neo4j Python driver is not installed. "
                "Run: pip install neo4j"
            ) from exc

        self._driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(
                settings.neo4j_username,
                settings.neo4j_password,
            ),
        )

    def close(self) -> None:
        self._driver.close()

    def verify_connectivity(self) -> None:
        self._driver.verify_connectivity()

    def upsert_node(
        self,
        *,
        key: str,
        label: str,
        name: str,
        properties: dict[str, Any],
    ) -> None:
        """
        Create/update one graph node.

        Dynamic labels are accepted only after strict allow-list validation.
        """

        safe_label = validate_node_label(
            label
        )

        safe_properties = (
            _neo4j_safe_properties(
                properties
            )
        )

        query = (
            f"MERGE (n:{safe_label} "
            "{key: $key}) "
            "SET n.name = $name, "
            "n += $properties "
            "RETURN n.key AS key"
        )

        with self._driver.session() as session:
            session.run(
                query,
                key=key,
                name=name,
                properties=safe_properties,
            ).consume()

    def upsert_edge(
        self,
        *,
        source_key: str,
        target_key: str,
        relationship_type: str,
        properties: dict[str, Any],
    ) -> None:
        """
        Create/update one evidence-aware graph relationship.

        Nested evidence such as `details` is serialized to JSON before being
        stored because Neo4j relationship properties cannot contain maps.
        """

        safe_rel = (
            validate_relationship_type(
                relationship_type
            )
        )

        properties = dict(properties)

        # Preserve structured relationship evidence explicitly.
        #
        # Example input:
        #
        # details = {
        #     "privilege_increase": False
        # }
        #
        # becomes:
        #
        # details_json = '{"privilege_increase": false}'
        #
        # The attack path analyzer converts it back to a dictionary.
        if "details" in properties:
            details = properties.pop(
                "details"
            )

            properties[
                "details_json"
            ] = json.dumps(
                details or {},
                sort_keys=True,
                default=str,
            )

        safe_properties = (
            _neo4j_safe_properties(
                properties
            )
        )

        query = (
            "MATCH "
            "(a {key: $source_key}), "
            "(b {key: $target_key}) "
            f"MERGE (a)-[r:{safe_rel}]->(b) "
            "SET r += $properties "
            "RETURN type(r) AS relationship_type"
        )

        with self._driver.session() as session:
            session.run(
                query,
                source_key=source_key,
                target_key=target_key,
                properties=safe_properties,
            ).consume()

    def find_paths(
        self,
        *,
        start_node_key: str,
        destination_node_key: str | None,
        max_depth: int,
        only_high_value_destinations: bool,
        scenario: str,
    ) -> list[dict]:
        """
        Return directed evidence paths from Neo4j.

        Path discovery is analytical only. Finding a graph path never means
        exploitation succeeded.
        """

        if max_depth < 1 or max_depth > 12:
            raise ValueError(
                "max_depth must be between 1 and 12."
            )

        destination_clause = ""

        params: dict[str, Any] = {
            "start_node_key": (
                start_node_key
            ),
            "scenario": scenario,
        }

        if destination_node_key:
            destination_clause += (
                " AND "
                "target.key = "
                "$destination_node_key"
            )

            params[
                "destination_node_key"
            ] = destination_node_key

        if only_high_value_destinations:
            destination_clause += (
                " AND "
                "("
                "target:SensitiveAsset "
                "OR "
                "coalesce("
                "target.high_value, "
                "false"
                ") = true"
                ")"
            )

        # max_depth is already strictly integer validated between 1 and 12.
        #
        # Neo4j does not accept a normal query parameter for the relationship
        # traversal bound, therefore the validated integer is interpolated.
        query = f"""
        MATCH (
            start {{
                key: $start_node_key
            }}
        )

        MATCH path=
            (start)-[*1..{max_depth}]->(target)

        WHERE
            ALL(
                r IN relationships(path)
                WHERE r.scenario = $scenario
            )
            {destination_clause}

        RETURN
            [
                n IN nodes(path)
                |
                {{
                    key: n.key,
                    name: n.name,
                    labels: labels(n),
                    properties: properties(n)
                }}
            ] AS nodes,

            [
                r IN relationships(path)
                |
                {{
                    relationship_type: type(r),
                    properties: properties(r)
                }}
            ] AS relationships

        LIMIT 100
        """

        with self._driver.session() as session:
            result = session.run(
                query,
                **params,
            )

            return [
                record.data()
                for record in result
            ]