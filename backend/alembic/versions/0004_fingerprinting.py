"""operating-system and technology fingerprinting

Revision ID: 0004_fingerprinting
Revises: 0003_service_enum
Create Date: 2026-10-11
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0004_fingerprinting"
down_revision: Union[str, None] = "0003_service_enum"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "fingerprint_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("explicitly_authorized", sa.Boolean(), nullable=False),
        sa.Column("run_nmap_os", sa.Boolean(), nullable=False),
        sa.Column("run_whatweb", sa.Boolean(), nullable=False),
        sa.Column("collect_http_headers", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("warning_message", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_fingerprint_jobs_asset", "fingerprint_jobs", ["asset_id"])
    op.create_index("ix_fingerprint_jobs_created_at", "fingerprint_jobs", ["created_at"])

    op.create_table(
        "technologies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("canonical_key", sa.String(length=300), nullable=False, unique=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("product_family", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_technologies_category", "technologies", ["category"])

    op.create_table(
        "technology_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("fingerprint_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("fingerprint_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("technology_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("technologies.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("observed_name", sa.String(length=255), nullable=False),
        sa.Column("observed_version", sa.String(length=255), nullable=True),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("conflict_state", sa.String(length=32), nullable=False),
        sa.Column("is_preferred", sa.Boolean(), nullable=False),
        sa.Column("is_legacy", sa.Boolean(), nullable=True),
        sa.Column("lifecycle_note", sa.Text(), nullable=True),
        sa.Column("evidence_summary_json", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_technology_observations_asset", "technology_observations", ["asset_id"])
    op.create_index("ix_technology_observations_job", "technology_observations", ["fingerprint_job_id"])
    op.create_index("ix_technology_observations_technology", "technology_observations", ["technology_id"])

    op.create_table(
        "fingerprint_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("fingerprint_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("fingerprint_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("technology_observation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("technology_observations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("source_locator", sa.String(length=512), nullable=True),
        sa.Column("observed_value", sa.Text(), nullable=False),
        sa.Column("version_evidence", sa.String(length=255), nullable=True),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("raw_evidence", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_fingerprint_evidence_job", "fingerprint_evidence", ["fingerprint_job_id"])
    op.create_index("ix_fingerprint_evidence_asset", "fingerprint_evidence", ["asset_id"])
    op.create_index("ix_fingerprint_evidence_observation", "fingerprint_evidence", ["technology_observation_id"])


def downgrade() -> None:
    op.drop_index("ix_fingerprint_evidence_observation", table_name="fingerprint_evidence")
    op.drop_index("ix_fingerprint_evidence_asset", table_name="fingerprint_evidence")
    op.drop_index("ix_fingerprint_evidence_job", table_name="fingerprint_evidence")
    op.drop_table("fingerprint_evidence")
    op.drop_index("ix_technology_observations_technology", table_name="technology_observations")
    op.drop_index("ix_technology_observations_job", table_name="technology_observations")
    op.drop_index("ix_technology_observations_asset", table_name="technology_observations")
    op.drop_table("technology_observations")
    op.drop_index("ix_technologies_category", table_name="technologies")
    op.drop_table("technologies")
    op.drop_index("ix_fingerprint_jobs_created_at", table_name="fingerprint_jobs")
    op.drop_index("ix_fingerprint_jobs_asset", table_name="fingerprint_jobs")
    op.drop_table("fingerprint_jobs")
