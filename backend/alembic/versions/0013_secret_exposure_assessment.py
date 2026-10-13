"""secret exposure assessment

Revision ID: 0013_secret_exposure_assessment
Revises: 0012_tls_security_assessment
Create Date: 2026-10-13
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0013_secret_exposure_assessment"
down_revision: Union[str, None] = "0012_tls_security_assessment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "secret_scan_imports",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("asset_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("assets.id",ondelete="SET NULL"),nullable=True),
        sa.Column("source_type",sa.String(length=64),nullable=False),
        sa.Column("source_name",sa.String(length=512),nullable=False),
        sa.Column("status",sa.String(length=32),nullable=False),
        sa.Column("candidate_count",sa.Integer(),nullable=False),
        sa.Column("finding_count",sa.Integer(),nullable=False),
        sa.Column("suppressed_count",sa.Integer(),nullable=False),
        sa.Column("imported_at",sa.DateTime(timezone=True),nullable=False),
    )
    op.create_index("ix_secret_scan_asset","secret_scan_imports",["asset_id"])

    op.create_table(
        "secret_exposures",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("import_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("secret_scan_imports.id",ondelete="CASCADE"),nullable=False),
        sa.Column("secret_type",sa.String(length=96),nullable=False),
        sa.Column("masked_fingerprint",sa.String(length=160),nullable=False),
        sa.Column("location",sa.Text(),nullable=False),
        sa.Column("evidence_hash",sa.String(length=64),nullable=False),
        sa.Column("severity",sa.String(length=32),nullable=False),
        sa.Column("validation_status",sa.String(length=32),nullable=False),
        sa.Column("first_seen",sa.DateTime(timezone=True),nullable=False),
        sa.Column("last_seen",sa.DateTime(timezone=True),nullable=False),
    )
    op.create_index("ix_secret_exposure_hash","secret_exposures",["evidence_hash"])
    op.create_index("ix_secret_exposure_import","secret_exposures",["import_id"])

    op.create_table(
        "secret_attack_path_signals",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("exposure_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("secret_exposures.id",ondelete="CASCADE"),nullable=False),
        sa.Column("source_asset_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("assets.id",ondelete="SET NULL"),nullable=True),
        sa.Column("related_asset_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("assets.id",ondelete="SET NULL"),nullable=True),
        sa.Column("signal_type",sa.String(length=64),nullable=False),
        sa.Column("rationale",sa.Text(),nullable=False),
        sa.Column("confidence",sa.String(length=32),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
    )
    op.create_index("ix_secret_path_signal_exposure","secret_attack_path_signals",["exposure_id"])

def downgrade() -> None:
    op.drop_index("ix_secret_path_signal_exposure",table_name="secret_attack_path_signals")
    op.drop_table("secret_attack_path_signals")
    op.drop_index("ix_secret_exposure_import",table_name="secret_exposures")
    op.drop_index("ix_secret_exposure_hash",table_name="secret_exposures")
    op.drop_table("secret_exposures")
    op.drop_index("ix_secret_scan_asset",table_name="secret_scan_imports")
    op.drop_table("secret_scan_imports")
