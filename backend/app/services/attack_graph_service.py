from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attack_graph import AttackGraphSyncRun, AttackPathEvidence, AttackPathRecord
from app.schemas.attack_graph import GraphEdgeInput, GraphNodeInput
from app.services.attack_graph_neo4j import Neo4jAttackGraph
from app.services.attack_graph_scenarios import scenario_start_node
from app.services.attack_graph_validation import (
    validate_node_label,
    validate_relationship_type,
    validate_scenario,
)
from app.services.attack_path_analyzer import analyze_path


def sync_graph(
    db: Session,
    *,
    scenario: str,
    nodes: list[GraphNodeInput],
    edges: list[GraphEdgeInput],
):
    normalized_scenario = validate_scenario(scenario)
    graph = Neo4jAttackGraph()

    run = AttackGraphSyncRun(
        scenario=normalized_scenario,
        status="running",
        nodes_written=0,
        edges_written=0,
        source_summary={
            "requested_nodes": len(nodes),
            "requested_edges": len(edges),
        },
    )
    db.add(run)
    db.flush()

    nodes_written = 0
    edges_written = 0

    try:
        graph.verify_connectivity()

        start = scenario_start_node(normalized_scenario)
        graph.upsert_node(
            key=start["key"],
            label=start["label"],
            name=start["name"],
            properties=start["properties"],
        )
        nodes_written += 1

        known_keys = {start["key"]}

        for node in nodes:
            validate_node_label(node.label)
            graph.upsert_node(
                key=node.key,
                label=node.label,
                name=node.name,
                properties={
                    **node.properties,
                    "scenario": normalized_scenario,
                },
            )
            known_keys.add(node.key)
            nodes_written += 1

        for edge in edges:
            validate_relationship_type(edge.relationship_type)

            if edge.source_key not in known_keys or edge.target_key not in known_keys:
                raise ValueError(
                    f"Edge references an unknown node: "
                    f"{edge.source_key} -> {edge.target_key}"
                )

            graph.upsert_edge(
                source_key=edge.source_key,
                target_key=edge.target_key,
                relationship_type=edge.relationship_type,
                properties={
                    "scenario": normalized_scenario,
                    "evidence_status": edge.evidence_status,
                    "confidence": edge.confidence,
                    "source": edge.source,
                    "details": edge.details,
                },
            )
            edges_written += 1

        run.status = "completed"
        run.nodes_written = nodes_written
        run.edges_written = edges_written
        run.source_summary = {
            "requested_nodes": len(nodes),
            "requested_edges": len(edges),
            "scenario_start_node": start["key"],
        }

        db.commit()
        db.refresh(run)
        return run

    except Exception:
        db.rollback()
        raise
    finally:
        graph.close()


def calculate_paths(
    db: Session,
    *,
    sync_run_id,
    scenario: str,
    start_node_key: str,
    destination_node_key: str | None,
    max_depth: int,
    only_high_value_destinations: bool,
):
    sync_run = db.get(AttackGraphSyncRun, sync_run_id)
    if sync_run is None:
        raise ValueError("Attack graph sync run not found.")

    normalized_scenario = validate_scenario(scenario)

    graph = Neo4jAttackGraph()
    records: list[AttackPathRecord] = []

    try:
        graph.verify_connectivity()

        raw_paths = graph.find_paths(
            start_node_key=start_node_key,
            destination_node_key=destination_node_key,
            max_depth=max_depth,
            only_high_value_destinations=only_high_value_destinations,
            scenario=normalized_scenario,
        )

        for raw_path in raw_paths:
            analysis = analyze_path(raw_path)
            if not analysis.node_sequence:
                continue

            destination_key = analysis.node_sequence[-1]

            record = AttackPathRecord(
                sync_run_id=sync_run.id,
                scenario=normalized_scenario,
                start_node_key=start_node_key,
                destination_node_key=destination_key,
                path_length=analysis.path_length,
                entry_point_exposure=analysis.entry_point_exposure,
                weakest_control=analysis.weakest_control,
                critical_destination=analysis.critical_destination,
                enabling_findings=analysis.enabling_findings,
                credential_dependency=analysis.credential_dependency,
                privilege_increase=analysis.privilege_increase,
                reachable_high_value_asset=analysis.reachable_high_value_asset,
                path_status=analysis.path_status,
                confidence=analysis.confidence,
                confidence_score=analysis.confidence_score,
                evidence=analysis.evidence,
                node_sequence=analysis.node_sequence,
                relationship_sequence=analysis.relationship_sequence,
                rationale=analysis.rationale,
            )
            db.add(record)
            db.flush()

            for item in analysis.evidence:
                evidence = AttackPathEvidence(
                    path_id=record.id,
                    edge_index=item["edge_index"],
                    relationship_type=item["relationship_type"],
                    source_node_key=item["source_node_key"],
                    target_node_key=item["target_node_key"],
                    evidence_status=item["evidence_status"],
                    confidence=item["confidence"],
                    source=item["source"],
                    details=item["details"],
                )
                db.add(evidence)

            records.append(record)

        db.commit()

        for record in records:
            db.refresh(record)

        return records

    except Exception:
        db.rollback()
        raise
    finally:
        graph.close()


def list_sync_runs(db: Session):
    return list(
        db.scalars(
            select(AttackGraphSyncRun)
            .order_by(AttackGraphSyncRun.created_at.desc())
        ).all()
    )


def list_paths(db: Session, sync_run_id=None):
    query = select(AttackPathRecord)

    if sync_run_id is not None:
        query = query.where(
            AttackPathRecord.sync_run_id == sync_run_id
        )

    return list(
        db.scalars(
            query.order_by(AttackPathRecord.created_at.desc())
        ).all()
    )


def list_path_evidence(db: Session, path_id):
    return list(
        db.scalars(
            select(AttackPathEvidence)
            .where(AttackPathEvidence.path_id == path_id)
            .order_by(AttackPathEvidence.edge_index.asc())
        ).all()
    )
