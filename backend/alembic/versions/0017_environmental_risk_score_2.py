"""environmental risk score 2.0

Revision ID: 0017_environmental_risk_score_2
Revises: 0016_neo4j_attack_graph
Create Date: 2026-10-14
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0017_environmental_risk_score_2"
down_revision: Union[str, None] = "0016_neo4j_attack_graph"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "risk_score_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("version_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("experimental", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("weights", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("interaction_rules", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "environmental_risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("vulnerability_id", sa.String(length=128), nullable=True),
        sa.Column("score_version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("risk_score_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("calculation_version", sa.String(length=64), nullable=False),
        sa.Column("raw_factors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("normalized_factors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("weights", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("base_score", sa.Float(), nullable=False),
        sa.Column("interaction_adjustment", sa.Float(), nullable=False),
        sa.Column("final_score", sa.Float(), nullable=False),
        sa.Column("priority_tier", sa.String(length=8), nullable=False),
        sa.Column("experimental", sa.Boolean(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "environmental_risk_contributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("score_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("environmental_risk_scores.id", ondelete="CASCADE"), nullable=False),
        sa.Column("factor_name", sa.String(length=128), nullable=False),
        sa.Column("contribution_type", sa.String(length=32), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=False),
        sa.Column("normalized_value", sa.Float(), nullable=True),
        sa.Column("configured_weight", sa.Float(), nullable=True),
        sa.Column("contribution", sa.Float(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
    )

    op.create_index("ix_environmental_risk_score_priority", "environmental_risk_scores", ["priority_tier"])
    op.create_index("ix_environmental_risk_score_asset", "environmental_risk_scores", ["asset_id"])
    op.create_index("ix_environmental_risk_contribution_score", "environmental_risk_contributions", ["score_id"])


def downgrade() -> None:
    op.drop_index("ix_environmental_risk_contribution_score", table_name="environmental_risk_contributions")
    op.drop_table("environmental_risk_contributions")
    op.drop_index("ix_environmental_risk_score_asset", table_name="environmental_risk_scores")
    op.drop_index("ix_environmental_risk_score_priority", table_name="environmental_risk_scores")
    op.drop_table("environmental_risk_scores")
    op.drop_table("risk_score_versions")
