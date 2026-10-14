"""remediation engineering and final evaluation

Revision ID: 0020_remediation_and_evaluation
Revises: 0019_grounded_vulnforge_analyst
Create Date: 2026-10-14
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0020_remediation_and_evaluation"
down_revision: Union[str, None] = "0019_grounded_vulnforge_analyst"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "remediation_cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_ref", sa.String(160), nullable=False),
        sa.Column("finding_type", sa.String(64), nullable=False),
        sa.Column("vulnerability_id", sa.String(128), nullable=True),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("technical_remediation", sa.Text(), nullable=False),
        sa.Column("temporary_mitigation", sa.Text(), nullable=True),
        sa.Column("affected_assets", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("sla_days", sa.Integer(), nullable=False),
        sa.Column("priority", sa.String(8), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=False),
        sa.Column("verification_procedure", sa.Text(), nullable=False),
        sa.Column("rollback_notes", sa.Text(), nullable=True),
        sa.Column("expected_risk_reduction", sa.Float(), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("risk_acceptance_reason", sa.Text(), nullable=True),
        sa.Column("deferral_reason", sa.Text(), nullable=True),
        sa.Column("false_positive_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_remediation_cases_finding_ref", "remediation_cases", ["finding_ref"])

    op.create_table(
        "remediation_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("evidence_stage", sa.String(32), nullable=False),
        sa.Column("evidence_type", sa.String(64), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("confidence", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_remediation_evidence_case_id", "remediation_evidence", ["case_id"])

    op.create_table(
        "reassessment_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("before_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("after_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("before_score", sa.Float(), nullable=False),
        sa.Column("after_score", sa.Float(), nullable=False),
        sa.Column("risk_delta", sa.Float(), nullable=False),
        sa.Column("before_attack_path", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("after_attack_path", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("attack_path_change", sa.String(64), nullable=False),
        sa.Column("before_controls", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("after_controls", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("control_change", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("verification_success", sa.Boolean(), nullable=False),
        sa.Column("regression_detected", sa.Boolean(), nullable=False),
        sa.Column("regression_reasons", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_reassessment_runs_case_id", "reassessment_runs", ["case_id"])

    op.create_table(
        "remediation_status_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("from_status", sa.String(64), nullable=False),
        sa.Column("to_status", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_remediation_status_events_case_id", "remediation_status_events", ["case_id"])

    op.create_table(
        "evaluation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_name", sa.String(255), nullable=False),
        sa.Column("dataset_name", sa.String(255), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("experiment_table", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "evaluation_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "evaluation_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evaluation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("finding_ref", sa.String(160), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("kev", sa.Integer(), nullable=False),
        sa.Column("epss", sa.Float(), nullable=False),
        sa.Column("environmental_score", sa.Float(), nullable=False),
        sa.Column("expert_rank", sa.Integer(), nullable=False),
        sa.Column("predicted_applicable", sa.Integer(), nullable=False),
        sa.Column("applicable", sa.Integer(), nullable=False),
        sa.Column("attack_path_relevant", sa.Integer(), nullable=False),
        sa.Column("triage_seconds", sa.Float(), nullable=False),
        sa.Column("pre_remediation_risk", sa.Float(), nullable=False),
        sa.Column("post_remediation_risk", sa.Float(), nullable=False),
        sa.Column("ai_factual_correct", sa.Integer(), nullable=False),
        sa.Column("ai_unsupported_claim", sa.Integer(), nullable=False),
        sa.Column("security_rule_correct", sa.Integer(), nullable=False),
        sa.Column("verification_success", sa.Integer(), nullable=False),
    )
    op.create_index("ix_evaluation_findings_evaluation_run_id", "evaluation_findings", ["evaluation_run_id"])


def downgrade() -> None:
    op.drop_index("ix_evaluation_findings_evaluation_run_id", table_name="evaluation_findings")
    op.drop_table("evaluation_findings")
    op.drop_table("evaluation_runs")
    op.drop_index("ix_remediation_status_events_case_id", table_name="remediation_status_events")
    op.drop_table("remediation_status_events")
    op.drop_index("ix_reassessment_runs_case_id", table_name="reassessment_runs")
    op.drop_table("reassessment_runs")
    op.drop_index("ix_remediation_evidence_case_id", table_name="remediation_evidence")
    op.drop_table("remediation_evidence")
    op.drop_index("ix_remediation_cases_finding_ref", table_name="remediation_cases")
    op.drop_table("remediation_cases")
