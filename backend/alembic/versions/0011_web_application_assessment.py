"""web application assessment

Revision ID: 0011_web_application_assessment
Revises: 0010_configuration_assessment
Create Date: 2026-10-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0011_web_application_assessment"
down_revision: Union[str, None] = "0010_configuration_assessment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "web_assessment_imports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("scanner", sa.String(length=64), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("duplicate_count", sa.Integer(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_web_import_asset", "web_assessment_imports", ["asset_id"])
    op.create_index("ix_web_import_scanner", "web_assessment_imports", ["scanner"])

    op.create_table(
        "web_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("import_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("web_assessment_imports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scanner", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=True),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("parameter", sa.String(length=255), nullable=True),
        sa.Column("request_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("response_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence_text", sa.Text(), nullable=True),
        sa.Column("raw_redacted", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("dedupe_key", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("dedupe_key", name="uq_web_evidence_dedupe_key"),
    )
    op.create_index("ix_web_evidence_import", "web_evidence", ["import_id"])
    op.create_index("ix_web_evidence_url", "web_evidence", ["url"])

    op.create_table(
        "web_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("import_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("web_assessment_imports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("web_evidence.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_type", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("owasp_top10", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("mapping_rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_web_findings_import", "web_findings", ["import_id"])
    op.create_index("ix_web_findings_type", "web_findings", ["finding_type"])


def downgrade() -> None:
    op.drop_index("ix_web_findings_type", table_name="web_findings")
    op.drop_index("ix_web_findings_import", table_name="web_findings")
    op.drop_table("web_findings")

    op.drop_index("ix_web_evidence_url", table_name="web_evidence")
    op.drop_index("ix_web_evidence_import", table_name="web_evidence")
    op.drop_table("web_evidence")

    op.drop_index("ix_web_import_scanner", table_name="web_assessment_imports")
    op.drop_index("ix_web_import_asset", table_name="web_assessment_imports")
    op.drop_table("web_assessment_imports")
