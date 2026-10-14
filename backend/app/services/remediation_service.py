from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.remediation import (
    ReassessmentRun,
    RemediationCase,
    RemediationEvidence,
    RemediationStatusEvent,
)
from app.services.reassessment_engine import compare_reassessment
from app.services.remediation_workflow import (
    apply_alternative_reason,
    mark_closed,
    validate_transition,
)


def create_case(db: Session, payload):
    row = RemediationCase(
        **payload.model_dump(),
        status="Open",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_cases(db: Session):
    return list(
        db.scalars(
            select(RemediationCase)
            .order_by(RemediationCase.created_at.desc())
        ).all()
    )


def get_case(db: Session, case_id):
    return db.get(RemediationCase, case_id)


def add_evidence(db: Session, case_id, payload):
    case = get_case(db, case_id)
    if case is None:
        raise ValueError("Remediation case not found.")

    row = RemediationEvidence(
        case_id=case_id,
        **payload.model_dump(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_evidence(db: Session, case_id):
    return list(
        db.scalars(
            select(RemediationEvidence)
            .where(RemediationEvidence.case_id == case_id)
            .order_by(RemediationEvidence.created_at.asc())
        ).all()
    )


def list_reassessments(db: Session, case_id):
    return list(
        db.scalars(
            select(ReassessmentRun)
            .where(ReassessmentRun.case_id == case_id)
            .order_by(ReassessmentRun.created_at.asc())
        ).all()
    )


def run_reassessment(db: Session, case_id, payload):
    case = get_case(db, case_id)
    if case is None:
        raise ValueError("Remediation case not found.")

    comparison = compare_reassessment(
        before_score=payload.before_score,
        after_score=payload.after_score,
        before_evidence=payload.before_evidence,
        after_evidence=payload.after_evidence,
        before_attack_path=payload.before_attack_path,
        after_attack_path=payload.after_attack_path,
        before_controls=payload.before_controls,
        after_controls=payload.after_controls,
    )

    row = ReassessmentRun(
        case_id=case_id,
        before_evidence=payload.before_evidence,
        after_evidence=payload.after_evidence,
        before_score=payload.before_score,
        after_score=payload.after_score,
        risk_delta=comparison.risk_delta,
        before_attack_path=payload.before_attack_path,
        after_attack_path=payload.after_attack_path,
        attack_path_change=comparison.attack_path_change,
        before_controls=payload.before_controls,
        after_controls=payload.after_controls,
        control_change=comparison.control_change,
        verification_success=comparison.verification_success,
        regression_detected=comparison.regression_detected,
        regression_reasons=comparison.regression_reasons,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def transition_case(db: Session, case_id, payload):
    case = get_case(db, case_id)
    if case is None:
        raise ValueError("Remediation case not found.")

    closure_evidence = db.scalar(
        select(RemediationEvidence.id)
        .where(
            RemediationEvidence.case_id == case_id,
            RemediationEvidence.evidence_stage == "closure",
        )
        .limit(1)
    ) is not None

    successful_reassessment = db.scalar(
        select(ReassessmentRun.id)
        .where(
            ReassessmentRun.case_id == case_id,
            ReassessmentRun.verification_success.is_(True),
            ReassessmentRun.regression_detected.is_(False),
        )
        .limit(1)
    ) is not None

    validate_transition(
        case.status,
        payload.to_status,
        has_closure_evidence=closure_evidence,
        has_successful_reassessment=successful_reassessment,
    )

    old_status = case.status
    case.status = payload.to_status
    apply_alternative_reason(case, payload.to_status, payload.reason)

    if payload.to_status == "Closed":
        mark_closed(case)

    db.add(
        RemediationStatusEvent(
            case_id=case.id,
            from_status=old_status,
            to_status=payload.to_status,
            actor=payload.actor,
            reason=payload.reason,
        )
    )
    db.commit()
    db.refresh(case)
    return case
