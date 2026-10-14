"""security control awareness

Revision ID: 0018_security_control_awareness
Revises: 0017_environmental_risk_score_2
Create Date: 2026-10-14
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0018_security_control_awareness"
down_revision: Union[str, None] = "0017_environmental_risk_score_2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "security_controls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("control_type", sa.String(64), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("effectiveness", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("temporary", sa.Boolean(), nullable=False),
        sa.Column("effective_from", sa.Date(), nullable=True),
        sa.Column("expires_at", sa.Date(), nullable=True),
        sa.Column("mitigation_until", sa.Date(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "control_risk_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("vulnerability_id", sa.String(128), nullable=True),
        sa.Column("exposure_type", sa.String(64), nullable=False),
        sa.Column("inherent_risk", sa.Float(), nullable=False),
        sa.Column("combined_control_effectiveness", sa.Float(), nullable=False),
        sa.Column("combined_control_confidence", sa.Float(), nullable=False),
        sa.Column("residual_risk", sa.Float(), nullable=False),
        sa.Column("calculation_version", sa.String(64), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "control_risk_contributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("control_risk_assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("security_controls.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("control_type", sa.String(64), nullable=False),
        sa.Column("control_owner", sa.String(255), nullable=False),
        sa.Column("effect", sa.String(32), nullable=False),
        sa.Column("control_effectiveness", sa.Float(), nullable=False),
        sa.Column("control_confidence", sa.Float(), nullable=False),
        sa.Column("effective_mitigation", sa.Float(), nullable=False),
        sa.Column("control_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("expired", sa.Boolean(), nullable=False),
        sa.Column("temporary", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.Date(), nullable=True),
        sa.Column("mitigation_until", sa.Date(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
    )
    op.create_index("ix_security_controls_asset", "security_controls", ["asset_id"])
    op.create_index("ix_control_risk_assessments_asset", "control_risk_assessments", ["asset_id"])
    op.create_index("ix_control_risk_contributions_assessment", "control_risk_contributions", ["assessment_id"])

def downgrade() -> None:
    op.drop_index("ix_control_risk_contributions_assessment", table_name="control_risk_contributions")
    op.drop_table("control_risk_contributions")
    op.drop_index("ix_control_risk_assessments_asset", table_name="control_risk_assessments")
    op.drop_table("control_risk_assessments")
    op.drop_index("ix_security_controls_asset", table_name="security_controls")
    op.drop_table("security_controls")
