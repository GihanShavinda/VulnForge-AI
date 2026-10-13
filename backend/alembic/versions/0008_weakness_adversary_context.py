"""weakness and adversary technique context

Revision ID: 0008_weakness_adversary_context
Revises: 0007_threat_intelligence
Create Date: 2026-10-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0008_weakness_adversary_context"
down_revision: Union[str, None] = "0007_threat_intelligence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("attack_id", sa.String(length=32), nullable=False, unique=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("tactic", sa.String(length=120), nullable=False),
        sa.Column("subtechnique_of", sa.String(length=32), nullable=True),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("source_url", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "weakness_capec_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cwe_id", sa.String(length=32), nullable=False),
        sa.Column("capec_id", sa.String(length=32), nullable=False),
        sa.Column("capec_name", sa.String(length=255), nullable=False),
        sa.Column("mapping_confidence", sa.String(length=32), nullable=False),
        sa.Column("mapping_source", sa.String(length=255), nullable=False),
        sa.Column("mapping_rationale", sa.Text(), nullable=False),
        sa.Column("source_url", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("cwe_id", "capec_id", name="uq_weakness_capec"),
    )

    op.create_table(
        "weakness_technique_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=128), nullable=False),
        sa.Column("attack_id", sa.String(length=32), nullable=False),
        sa.Column("context_type", sa.String(length=32), nullable=False),
        sa.Column("mapping_confidence", sa.String(length=32), nullable=False),
        sa.Column("mapping_source", sa.String(length=255), nullable=False),
        sa.Column("mapping_rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("subject_type", "subject_id", "attack_id", name="uq_weakness_technique"),
    )

    op.create_table(
        "behaviour_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column("canonical_id", sa.String(length=128), nullable=True),
        sa.Column("attack_id", sa.String(length=32), nullable=False),
        sa.Column("context_type", sa.String(length=32), nullable=False),
        sa.Column("mapping_confidence", sa.String(length=32), nullable=False),
        sa.Column("mapping_source", sa.String(length=255), nullable=False),
        sa.Column("mapping_rationale", sa.Text(), nullable=False),
        sa.Column("evidence_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_weakness_capec_cwe", "weakness_capec_mappings", ["cwe_id"])
    op.create_index("ix_weakness_technique_subject", "weakness_technique_mappings", ["subject_type", "subject_id"])
    op.create_index("ix_behaviour_observation_finding", "behaviour_observations", ["finding_id"])
    op.create_index("ix_behaviour_observation_canonical", "behaviour_observations", ["canonical_id"])


def downgrade() -> None:
    op.drop_index("ix_behaviour_observation_canonical", table_name="behaviour_observations")
    op.drop_index("ix_behaviour_observation_finding", table_name="behaviour_observations")
    op.drop_table("behaviour_observations")

    op.drop_index("ix_weakness_technique_subject", table_name="weakness_technique_mappings")
    op.drop_table("weakness_technique_mappings")

    op.drop_index("ix_weakness_capec_cwe", table_name="weakness_capec_mappings")
    op.drop_table("weakness_capec_mappings")

    op.drop_table("attack_techniques")
