"""service and attack surface enumeration

Revision ID: 0003_service_attack_surface_enumeration
Revises: 0002_network_asset_discovery
Create Date: 2026-10-10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003_service_enum"
down_revision: Union[str, None] = "0002_network_asset_discovery"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "enumeration_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(length=128), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("top_ports", sa.Integer(), nullable=False),
        sa.Column("scan_source", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("command_args_json", sa.Text(), nullable=True),
        sa.Column("explicitly_authorized", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_enumeration_jobs_asset", "enumeration_jobs", ["asset_id"])
    op.create_index("ix_enumeration_jobs_created_at", "enumeration_jobs", ["created_at"])

    op.create_table(
        "service_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("enumeration_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("enumeration_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("service", sa.String(length=120), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=255), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("cpe", sa.Text(), nullable=True),
        sa.Column("tls_indicator", sa.Boolean(), nullable=False),
        sa.Column("scan_confidence", sa.Integer(), nullable=True),
        sa.Column("detection_source", sa.String(length=120), nullable=False),
        sa.Column("script_outputs_json", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_types", sa.Text(), nullable=True),
    )
    op.create_index("ix_service_observations_asset", "service_observations", ["asset_id"])
    op.create_index("ix_service_observations_endpoint", "service_observations", ["asset_id", "protocol", "port"])
    op.create_index("ix_service_observations_job", "service_observations", ["enumeration_job_id"])

    op.create_table(
        "enumeration_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("enumeration_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("enumeration_jobs.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("evidence_type", sa.String(length=32), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("raw_xml", sa.Text(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "exposure_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("enumeration_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("enumeration_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_observation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("service_observations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_code", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("conclusion", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_exposure_findings_asset", "exposure_findings", ["asset_id"])
    op.create_index("ix_exposure_findings_rule", "exposure_findings", ["rule_code"])


def downgrade() -> None:
    op.drop_index("ix_exposure_findings_rule", table_name="exposure_findings")
    op.drop_index("ix_exposure_findings_asset", table_name="exposure_findings")
    op.drop_table("exposure_findings")
    op.drop_table("enumeration_evidence")
    op.drop_index("ix_service_observations_job", table_name="service_observations")
    op.drop_index("ix_service_observations_endpoint", table_name="service_observations")
    op.drop_index("ix_service_observations_asset", table_name="service_observations")
    op.drop_table("service_observations")
    op.drop_index("ix_enumeration_jobs_created_at", table_name="enumeration_jobs")
    op.drop_index("ix_enumeration_jobs_asset", table_name="enumeration_jobs")
    op.drop_table("enumeration_jobs")
