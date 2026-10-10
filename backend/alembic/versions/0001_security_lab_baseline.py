"""security lab baseline

Revision ID: 0001_security_lab_baseline
Revises:
Create Date: 2026-10-07
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0001_security_lab_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "networks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("cidr", sa.String(length=64), nullable=False, unique=True),
        sa.Column("network_type", sa.String(length=32), nullable=False),
        sa.Column("approved_for_scanning", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "asset_tags",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=80), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
    )

    op.create_table(
        "credential_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("secret_reference", sa.String(length=500), nullable=False),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "scan_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("scanner_type", sa.String(length=64), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("max_concurrency", sa.Integer(), nullable=False),
        sa.Column("evidence_retention_days", sa.Integer(), nullable=False),
        sa.Column("require_scope_validation", sa.Boolean(), nullable=False),
        sa.Column("require_authorization", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("target", sa.String(length=500), nullable=True),
        sa.Column("allowed", sa.Boolean(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("details_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "network_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("networks.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("operating_system", sa.String(length=255), nullable=True),
        sa.Column("role", sa.String(length=120), nullable=True),
        sa.Column("is_vulnerable_target", sa.Boolean(), nullable=False),
        sa.Column("scanning_enabled", sa.Boolean(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("ip_address", name="uq_assets_ip_address"),
    )

    op.create_table(
        "scan_scopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column(
            "network_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("networks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("require_explicit_authorization", sa.Boolean(), nullable=False),
        sa.Column("maintenance_start", sa.Time(), nullable=True),
        sa.Column("maintenance_end", sa.Time(), nullable=True),
        sa.Column("timezone_name", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "asset_tag_links",
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "tag_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("asset_tags.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    op.create_index("ix_assets_network_id", "assets", ["network_id"])
    op.create_index("ix_scan_scopes_network_id", "scan_scopes", ["network_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_event_type", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_scan_scopes_network_id", table_name="scan_scopes")
    op.drop_index("ix_assets_network_id", table_name="assets")

    op.drop_table("asset_tag_links")
    op.drop_table("scan_scopes")
    op.drop_table("assets")
    op.drop_table("audit_logs")
    op.drop_table("scan_profiles")
    op.drop_table("credential_profiles")
    op.drop_table("asset_tags")
    op.drop_table("networks")
