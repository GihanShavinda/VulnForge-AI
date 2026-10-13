"""patch and lifecycle risk

Revision ID: 0014_patch_lifecycle_risk
Revises: 0013_secret_exposure_assessment
Create Date: 2026-10-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0014_patch_lifecycle_risk"
down_revision: Union[str, None] = "0013_secret_exposure_assessment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_lifecycle_assessment_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("patch_finding_count", sa.Integer(), nullable=False),
        sa.Column("lifecycle_finding_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_patch_lifecycle_run_asset", "patch_lifecycle_assessment_runs", ["asset_id"])

    op.create_table(
        "patch_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("patch_lifecycle_assessment_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("component", sa.String(length=255), nullable=False),
        sa.Column("installed_version", sa.String(length=255), nullable=True),
        sa.Column("fixed_version", sa.String(length=255), nullable=True),
        sa.Column("vulnerability_id", sa.String(length=128), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("risk_state", sa.String(length=64), nullable=False),
        sa.Column("patch_available", sa.Boolean(), nullable=True),
        sa.Column("vendor_backport", sa.Boolean(), nullable=False),
        sa.Column("reboot_required", sa.Boolean(), nullable=True),
        sa.Column("compensating_control", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_patch_finding_run", "patch_findings", ["run_id"])
    op.create_index("ix_patch_finding_state", "patch_findings", ["risk_state"])

    op.create_table(
        "lifecycle_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("patch_lifecycle_assessment_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=True),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("vendor_support_status", sa.String(length=64), nullable=False),
        sa.Column("end_of_support_date", sa.Date(), nullable=True),
        sa.Column("patch_availability", sa.String(length=64), nullable=False),
        sa.Column("accepted_legacy_system", sa.Boolean(), nullable=False),
        sa.Column("temporary_compensating_control", sa.Text(), nullable=True),
        sa.Column("vendor_backport", sa.Boolean(), nullable=False),
        sa.Column("replacement_recommendation", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_lifecycle_finding_run", "lifecycle_findings", ["run_id"])
    op.create_index("ix_lifecycle_support_status", "lifecycle_findings", ["vendor_support_status"])


def downgrade() -> None:
    op.drop_index("ix_lifecycle_support_status", table_name="lifecycle_findings")
    op.drop_index("ix_lifecycle_finding_run", table_name="lifecycle_findings")
    op.drop_table("lifecycle_findings")

    op.drop_index("ix_patch_finding_state", table_name="patch_findings")
    op.drop_index("ix_patch_finding_run", table_name="patch_findings")
    op.drop_table("patch_findings")

    op.drop_index("ix_patch_lifecycle_run_asset", table_name="patch_lifecycle_assessment_runs")
    op.drop_table("patch_lifecycle_assessment_runs")
