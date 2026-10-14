from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AttackGraphSyncRun(Base):
    __tablename__ = "attack_graph_sync_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scenario: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    nodes_written: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edges_written: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AttackPathRecord(Base):
    __tablename__ = "attack_path_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sync_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_graph_sync_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    scenario: Mapped[str] = mapped_column(String(64), nullable=False)
    start_node_key: Mapped[str] = mapped_column(String(255), nullable=False)
    destination_node_key: Mapped[str] = mapped_column(String(255), nullable=False)
    path_length: Mapped[int] = mapped_column(Integer, nullable=False)
    entry_point_exposure: Mapped[str] = mapped_column(String(32), nullable=False)
    weakest_control: Mapped[str | None] = mapped_column(String(255))
    critical_destination: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabling_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    credential_dependency: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    privilege_increase: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reachable_high_value_asset: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    path_status: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[list] = mapped_column(JSONB, nullable=False)
    node_sequence: Mapped[list] = mapped_column(JSONB, nullable=False)
    relationship_sequence: Mapped[list] = mapped_column(JSONB, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AttackPathEvidence(Base):
    __tablename__ = "attack_path_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    path_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_path_records.id", ondelete="CASCADE"),
        nullable=False,
    )
    edge_index: Mapped[int] = mapped_column(Integer, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_node_key: Mapped[str] = mapped_column(String(255), nullable=False)
    target_node_key: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
