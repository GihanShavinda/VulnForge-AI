"""network asset discovery

Revision ID: 0002_network_asset_discovery
Revises: 0001_security_lab_baseline
Create Date: 2026-10-08
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002_network_asset_discovery"
down_revision: Union[str, None] = "0001_security_lab_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("mac_address", sa.String(length=32), nullable=True))
    op.add_column("assets", sa.Column("vendor", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("reachable", sa.Boolean(), nullable=True))
    op.add_column("assets", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assets", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assets", sa.Column("last_discovery_source", sa.String(length=64), nullable=True))
    op.create_index("ix_assets_mac_address", "assets", ["mac_address"])
    op.create_index("ix_assets_hostname", "assets", ["hostname"])

    op.create_table(
        "discovery_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("target", sa.String(length=128), nullable=False),
        sa.Column("discovery_method", sa.String(length=32), nullable=False),
        sa.Column("scan_source", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("command_args_json", sa.Text(), nullable=True),
        sa.Column("explicitly_authorized", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_discovery_jobs_created_at", "discovery_jobs", ["created_at"])

    op.create_table(
        "discovered_hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("discovery_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("matched_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("mac_address", sa.String(length=32), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("reachable", sa.Boolean(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scan_source", sa.String(length=64), nullable=False),
        sa.Column("scan_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("identity_basis", sa.String(length=64), nullable=True),
        sa.Column("change_types", sa.Text(), nullable=True),
    )
    op.create_index("ix_discovered_hosts_job", "discovered_hosts", ["discovery_job_id"])
    op.create_index("ix_discovered_hosts_ip", "discovered_hosts", ["ip_address"])
    op.create_index("ix_discovered_hosts_mac", "discovered_hosts", ["mac_address"])

    op.create_table(
        "discovery_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("discovery_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("evidence_type", sa.String(length=32), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("raw_xml", sa.Text(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("discovery_evidence")
    op.drop_index("ix_discovered_hosts_mac", table_name="discovered_hosts")
    op.drop_index("ix_discovered_hosts_ip", table_name="discovered_hosts")
    op.drop_index("ix_discovered_hosts_job", table_name="discovered_hosts")
    op.drop_table("discovered_hosts")
    op.drop_index("ix_discovery_jobs_created_at", table_name="discovery_jobs")
    op.drop_table("discovery_jobs")

    op.drop_index("ix_assets_hostname", table_name="assets")
    op.drop_index("ix_assets_mac_address", table_name="assets")
    op.drop_column("assets", "last_discovery_source")
    op.drop_column("assets", "last_seen")
    op.drop_column("assets", "first_seen")
    op.drop_column("assets", "reachable")
    op.drop_column("assets", "vendor")
    op.drop_column("assets", "mac_address")
