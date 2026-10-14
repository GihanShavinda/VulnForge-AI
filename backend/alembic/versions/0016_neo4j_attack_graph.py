"""neo4j attack graph

Revision ID: 0016_neo4j_attack_graph
Revises: 0015_exploitability_evidence
Create Date: 2026-10-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0016_neo4j_attack_graph"
down_revision: Union[str, None] = "0015_exploitability_evidence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_graph_sync_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scenario", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("nodes_written", sa.Integer(), nullable=False),
        sa.Column("edges_written", sa.Integer(), nullable=False),
        sa.Column("source_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_attack_graph_sync_scenario",
        "attack_graph_sync_runs",
        ["scenario"],
    )

    op.create_table(
        "attack_path_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "sync_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_graph_sync_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scenario", sa.String(length=64), nullable=False),
        sa.Column("start_node_key", sa.String(length=255), nullable=False),
        sa.Column("destination_node_key", sa.String(length=255), nullable=False),
        sa.Column("path_length", sa.Integer(), nullable=False),
        sa.Column("entry_point_exposure", sa.String(length=32), nullable=False),
        sa.Column("weakest_control", sa.String(length=255), nullable=True),
        sa.Column("critical_destination", sa.Boolean(), nullable=False),
        sa.Column("enabling_findings", sa.Integer(), nullable=False),
        sa.Column("credential_dependency", sa.Boolean(), nullable=False),
        sa.Column("privilege_increase", sa.Boolean(), nullable=False),
        sa.Column("reachable_high_value_asset", sa.Boolean(), nullable=False),
        sa.Column("path_status", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("node_sequence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("relationship_sequence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_attack_path_sync_run",
        "attack_path_records",
        ["sync_run_id"],
    )
    op.create_index(
        "ix_attack_path_status",
        "attack_path_records",
        ["path_status"],
    )
    op.create_index(
        "ix_attack_path_destination",
        "attack_path_records",
        ["destination_node_key"],
    )

    op.create_table(
        "attack_path_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "path_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_path_records.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("edge_index", sa.Integer(), nullable=False),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("source_node_key", sa.String(length=255), nullable=False),
        sa.Column("target_node_key", sa.String(length=255), nullable=False),
        sa.Column("evidence_status", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_attack_path_evidence_path",
        "attack_path_evidence",
        ["path_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_attack_path_evidence_path",
        table_name="attack_path_evidence",
    )
    op.drop_table("attack_path_evidence")

    op.drop_index(
        "ix_attack_path_destination",
        table_name="attack_path_records",
    )
    op.drop_index(
        "ix_attack_path_status",
        table_name="attack_path_records",
    )
    op.drop_index(
        "ix_attack_path_sync_run",
        table_name="attack_path_records",
    )
    op.drop_table("attack_path_records")

    op.drop_index(
        "ix_attack_graph_sync_scenario",
        table_name="attack_graph_sync_runs",
    )
    op.drop_table("attack_graph_sync_runs")
