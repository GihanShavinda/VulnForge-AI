"""threat intelligence layer

Revision ID: 0007_threat_intelligence
Revises: 0006_sbom_package_vulnerability
Create Date: 2026-10-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0007_threat_intelligence"
down_revision: Union[str, None] = "0006_sbom_package_vulnerability"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=80), nullable=False, unique=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("base_url", sa.String(length=1024), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("freshness_minutes", sa.Integer(), nullable=False),
        sa.Column("cache_namespace", sa.String(length=120), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("etag", sa.String(length=512), nullable=True),
        sa.Column("last_modified", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_threat_intel_sources_type", "threat_intel_sources", ["source_type"], unique=True)

    op.create_table(
        "intel_sync_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_intel_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_identifiers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("fetched_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("normalized_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cache_used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    op.create_index("ix_intel_sync_runs_source", "intel_sync_runs", ["source_id"])
    op.create_index("ix_intel_sync_runs_started", "intel_sync_runs", ["started_at"])

    op.create_table(
        "threat_intel_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_intel_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sync_run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("intel_sync_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("canonical_id", sa.String(length=128), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("osv_id", sa.String(length=128), nullable=True),
        sa.Column("cwes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cvss31_score", sa.Float(), nullable=True),
        sa.Column("cvss31_vector", sa.String(length=512), nullable=True),
        sa.Column("cvss4_score", sa.Float(), nullable=True),
        sa.Column("cvss4_vector", sa.String(length=512), nullable=True),
        sa.Column("cpes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("affected_ranges", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("fixed_ranges", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("vendor_advisories", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("known_ransomware_use", sa.Boolean(), nullable=True),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("raw_sha256", sa.String(length=64), nullable=False),
        sa.Column("raw_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source_record_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source_id", "canonical_id", "raw_sha256", name="uq_threat_intel_source_canonical_hash"),
    )
    op.create_index("ix_threat_intel_obs_canonical", "threat_intel_observations", ["canonical_id"])
    op.create_index("ix_threat_intel_obs_cve", "threat_intel_observations", ["cve_id"])
    op.create_index("ix_threat_intel_obs_osv", "threat_intel_observations", ["osv_id"])
    op.create_index("ix_threat_intel_obs_source", "threat_intel_observations", ["source_id"])
    op.create_index("ix_threat_intel_obs_observed", "threat_intel_observations", ["observed_at"])

    op.create_table(
        "intel_conflicts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("canonical_id", sa.String(length=128), nullable=False),
        sa.Column("field_name", sa.String(length=120), nullable=False),
        sa.Column("source_values", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("resolution_state", sa.String(length=32), nullable=False),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_intel_conflicts_canonical", "intel_conflicts", ["canonical_id"])
    op.create_index("ix_intel_conflicts_state", "intel_conflicts", ["resolution_state"])


def downgrade() -> None:
    op.drop_index("ix_intel_conflicts_state", table_name="intel_conflicts")
    op.drop_index("ix_intel_conflicts_canonical", table_name="intel_conflicts")
    op.drop_table("intel_conflicts")

    op.drop_index("ix_threat_intel_obs_observed", table_name="threat_intel_observations")
    op.drop_index("ix_threat_intel_obs_source", table_name="threat_intel_observations")
    op.drop_index("ix_threat_intel_obs_osv", table_name="threat_intel_observations")
    op.drop_index("ix_threat_intel_obs_cve", table_name="threat_intel_observations")
    op.drop_index("ix_threat_intel_obs_canonical", table_name="threat_intel_observations")
    op.drop_table("threat_intel_observations")

    op.drop_index("ix_intel_sync_runs_started", table_name="intel_sync_runs")
    op.drop_index("ix_intel_sync_runs_source", table_name="intel_sync_runs")
    op.drop_table("intel_sync_runs")

    op.drop_index("ix_threat_intel_sources_type", table_name="threat_intel_sources")
    op.drop_table("threat_intel_sources")
