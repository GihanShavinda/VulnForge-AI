"""configuration vulnerability assessment

Revision ID: 0010_configuration_assessment
Revises: 0009_vulnerability_severity
Create Date: 2026-10-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0010_configuration_assessment"
down_revision: Union[str, None] = "0009_vulnerability_severity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "benchmark_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("platform", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("controls", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "config_assessment_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("benchmark_profiles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_config_assessment_asset", "config_assessment_runs", ["asset_id"])
    op.create_index("ix_config_assessment_profile", "config_assessment_runs", ["profile_id"])

    op.create_table(
        "config_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("config_assessment_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control_id", sa.String(length=128), nullable=True),
        sa.Column("category", sa.String(length=120), nullable=False),
        sa.Column("observed_value", sa.Text(), nullable=False),
        sa.Column("source_locator", sa.String(length=512), nullable=True),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("raw_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_config_evidence_assessment", "config_evidence", ["assessment_id"])
    op.create_index("ix_config_evidence_control", "config_evidence", ["control_id"])

    op.create_table(
        "configuration_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("config_assessment_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control", sa.String(length=160), nullable=False),
        sa.Column("expected_state", sa.Text(), nullable=False),
        sa.Column("observed_state", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("framework_reference", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_configuration_findings_assessment", "configuration_findings", ["assessment_id"])
    op.create_index("ix_configuration_findings_severity", "configuration_findings", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_configuration_findings_severity", table_name="configuration_findings")
    op.drop_index("ix_configuration_findings_assessment", table_name="configuration_findings")
    op.drop_table("configuration_findings")

    op.drop_index("ix_config_evidence_control", table_name="config_evidence")
    op.drop_index("ix_config_evidence_assessment", table_name="config_evidence")
    op.drop_table("config_evidence")

    op.drop_index("ix_config_assessment_profile", table_name="config_assessment_runs")
    op.drop_index("ix_config_assessment_asset", table_name="config_assessment_runs")
    op.drop_table("config_assessment_runs")

    op.drop_table("benchmark_profiles")
