"""tls security assessment

Revision ID: 0012_tls_security_assessment
Revises: 0011_web_application_assessment
Create Date: 2026-10-13
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0012_tls_security_assessment"
down_revision: Union[str, None] = "0011_web_application_assessment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "tls_assessment_imports",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("asset_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("assets.id",ondelete="SET NULL"),nullable=True),
        sa.Column("target",sa.String(length=512),nullable=False),
        sa.Column("port",sa.Integer(),nullable=False),
        sa.Column("scanner",sa.String(length=64),nullable=False),
        sa.Column("source_name",sa.String(length=255),nullable=False),
        sa.Column("status",sa.String(length=32),nullable=False),
        sa.Column("evidence_count",sa.Integer(),nullable=False),
        sa.Column("finding_count",sa.Integer(),nullable=False),
        sa.Column("lab_context",sa.Boolean(),nullable=False),
        sa.Column("imported_at",sa.DateTime(timezone=True),nullable=False),
    )
    op.create_index("ix_tls_import_asset","tls_assessment_imports",["asset_id"])
    op.create_index("ix_tls_import_target","tls_assessment_imports",["target","port"])
    op.create_table(
        "tls_evidence",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("import_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("tls_assessment_imports.id",ondelete="CASCADE"),nullable=False),
        sa.Column("category",sa.String(length=128),nullable=False),
        sa.Column("observed_value",sa.Text(),nullable=False),
        sa.Column("source_locator",sa.String(length=512),nullable=True),
        sa.Column("confidence",sa.String(length=32),nullable=False),
        sa.Column("raw_json",postgresql.JSONB(astext_type=sa.Text()),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
    )
    op.create_index("ix_tls_evidence_import","tls_evidence",["import_id"])
    op.create_index("ix_tls_evidence_category","tls_evidence",["category"])
    op.create_table(
        "crypto_findings",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("import_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("tls_assessment_imports.id",ondelete="CASCADE"),nullable=False),
        sa.Column("finding_type",sa.String(length=64),nullable=False),
        sa.Column("control",sa.String(length=180),nullable=False),
        sa.Column("observed_state",sa.Text(),nullable=False),
        sa.Column("evidence",postgresql.JSONB(astext_type=sa.Text()),nullable=False),
        sa.Column("severity",sa.String(length=32),nullable=False),
        sa.Column("remediation",sa.Text(),nullable=False),
        sa.Column("confidence",sa.String(length=32),nullable=False),
        sa.Column("acceptable_lab_configuration",sa.Boolean(),nullable=False),
        sa.Column("rationale",sa.Text(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
    )
    op.create_index("ix_crypto_findings_import","crypto_findings",["import_id"])
    op.create_index("ix_crypto_findings_type","crypto_findings",["finding_type"])

def downgrade() -> None:
    op.drop_index("ix_crypto_findings_type",table_name="crypto_findings")
    op.drop_index("ix_crypto_findings_import",table_name="crypto_findings")
    op.drop_table("crypto_findings")
    op.drop_index("ix_tls_evidence_category",table_name="tls_evidence")
    op.drop_index("ix_tls_evidence_import",table_name="tls_evidence")
    op.drop_table("tls_evidence")
    op.drop_index("ix_tls_import_target",table_name="tls_assessment_imports")
    op.drop_index("ix_tls_import_asset",table_name="tls_assessment_imports")
    op.drop_table("tls_assessment_imports")
