"""grounded VulnForge AI analyst

Revision ID: 0019_grounded_vulnforge_analyst
Revises: 0018_security_control_awareness
Create Date: 2026-10-14
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0019_grounded_vulnforge_analyst"
down_revision: Union[str, None] = "0018_security_control_awareness"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "grounded_analyst_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("calculation_version", sa.String(64), nullable=False),
        sa.Column("model_name", sa.String(128), nullable=False),
        sa.Column("fallback_used", sa.Boolean(), nullable=False),
        sa.Column("input_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("output_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("grounding_status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "grounded_analyst_audits",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("grounded_analyst_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("evidence_id", sa.String(128), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_grounded_analyst_audits_run_id",
        "grounded_analyst_audits",
        ["run_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_grounded_analyst_audits_run_id",
        table_name="grounded_analyst_audits",
    )
    op.drop_table("grounded_analyst_audits")
    op.drop_table("grounded_analyst_runs")
