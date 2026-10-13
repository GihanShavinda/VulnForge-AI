"""credentialed authenticated assessment

Revision ID: 0005_authenticated_assessment
Revises: 0004_fingerprinting
Create Date: 2026-10-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0005_authenticated_assessment"
down_revision: Union[str, None] = "0004_fingerprinting"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("credential_profiles", sa.Column("auth_method", sa.String(length=32), nullable=False, server_default="password"))
    op.add_column("credential_profiles", sa.Column("port", sa.Integer(), nullable=True))
    op.add_column("credential_profiles", sa.Column("encrypted_secret", sa.Text(), nullable=True))
    op.add_column("credential_profiles", sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("credential_profiles", sa.Column("max_failed_attempts", sa.Integer(), nullable=False, server_default="3"))
    op.add_column("credential_profiles", sa.Column("lockout_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("credential_profiles", sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "authenticated_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("credential_profiles.id", ondelete="SET NULL"), nullable=True),
        sa.Column("transport", sa.String(length=32), nullable=False),
        sa.Column("collection_mode", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("explicitly_authorized", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_authenticated_scans_asset", "authenticated_scans", ["asset_id"])
    op.create_index("ix_authenticated_scans_created_at", "authenticated_scans", ["created_at"])

    op.create_table(
        "authenticated_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("authenticated_scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("authenticated_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("source_locator", sa.String(length=512), nullable=True),
        sa.Column("observed_value", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_authenticated_evidence_scan", "authenticated_evidence", ["authenticated_scan_id"])
    op.create_index("ix_authenticated_evidence_asset", "authenticated_evidence", ["asset_id"])
    op.create_index("ix_authenticated_evidence_category", "authenticated_evidence", ["category"])

    op.create_table(
        "credential_use_audits",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("credential_profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("credential_profiles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("authenticated_scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("authenticated_scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("remote_address", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_credential_use_audits_profile", "credential_use_audits", ["credential_profile_id"])
    op.create_index("ix_credential_use_audits_asset", "credential_use_audits", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_credential_use_audits_asset", table_name="credential_use_audits")
    op.drop_index("ix_credential_use_audits_profile", table_name="credential_use_audits")
    op.drop_table("credential_use_audits")
    op.drop_index("ix_authenticated_evidence_category", table_name="authenticated_evidence")
    op.drop_index("ix_authenticated_evidence_asset", table_name="authenticated_evidence")
    op.drop_index("ix_authenticated_evidence_scan", table_name="authenticated_evidence")
    op.drop_table("authenticated_evidence")
    op.drop_index("ix_authenticated_scans_created_at", table_name="authenticated_scans")
    op.drop_index("ix_authenticated_scans_asset", table_name="authenticated_scans")
    op.drop_table("authenticated_scans")
    op.drop_column("credential_profiles", "last_used_at")
    op.drop_column("credential_profiles", "lockout_until")
    op.drop_column("credential_profiles", "max_failed_attempts")
    op.drop_column("credential_profiles", "failed_attempts")
    op.drop_column("credential_profiles", "encrypted_secret")
    op.drop_column("credential_profiles", "port")
    op.drop_column("credential_profiles", "auth_method")
