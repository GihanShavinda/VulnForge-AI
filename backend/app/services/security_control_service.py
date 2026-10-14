from __future__ import annotations
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.security_control_awareness import SecurityControl, ControlRiskAssessment, ControlRiskContribution
from app.models.security_lab import Asset
from app.services.security_control_risk import calculate_residual_risk

def create_control(db: Session, payload):
    if payload.asset_id is not None and db.get(Asset, payload.asset_id) is None:
        raise ValueError("Asset not found.")
    row = SecurityControl(**payload.model_dump())
    db.add(row); db.commit(); db.refresh(row)
    return row

def list_controls(db: Session, asset_id=None):
    stmt = select(SecurityControl).order_by(SecurityControl.created_at.desc())
    if asset_id is not None:
        stmt = stmt.where(SecurityControl.asset_id == asset_id)
    return list(db.scalars(stmt).all())

def calculate_and_store_assessment(db: Session, payload):
    if payload.asset_id is not None and db.get(Asset, payload.asset_id) is None:
        raise ValueError("Asset not found.")

    controls = []
    for control_id in payload.control_ids:
        control = db.get(SecurityControl, control_id)
        if control is None:
            raise ValueError(f"Security control not found: {control_id}")
        if payload.asset_id is not None and control.asset_id not in {None, payload.asset_id}:
            raise ValueError(f"Control {control_id} does not apply to the requested asset.")
        controls.append(control)

    calc = calculate_residual_risk(
        inherent_risk=payload.inherent_risk,
        exposure_type=payload.exposure_type,
        controls=controls,
    )

    assessment = ControlRiskAssessment(
        asset_id=payload.asset_id,
        vulnerability_id=payload.vulnerability_id,
        exposure_type=payload.exposure_type,
        inherent_risk=calc.inherent_risk,
        combined_control_effectiveness=calc.combined_control_effectiveness,
        combined_control_confidence=calc.combined_control_confidence,
        residual_risk=calc.residual_risk,
        calculation_version=payload.calculation_version,
        rationale=calc.rationale,
    )
    db.add(assessment); db.flush()

    rows = []
    for item in calc.controls:
        row = ControlRiskContribution(
            assessment_id=assessment.id,
            control_id=item.control_id,
            control_type=item.control_type,
            control_owner=item.owner,
            effect=item.effect,
            control_effectiveness=item.effectiveness,
            control_confidence=item.confidence,
            effective_mitigation=item.effective_mitigation,
            control_evidence=item.evidence,
            expired=item.expired,
            temporary=item.temporary,
            expires_at=item.expires_at,
            mitigation_until=item.mitigation_until,
            reason=item.reason,
        )
        db.add(row); rows.append(row)

    db.commit(); db.refresh(assessment)
    for row in rows: db.refresh(row)
    return assessment, rows

def list_assessments(db: Session):
    return list(db.scalars(select(ControlRiskAssessment).order_by(ControlRiskAssessment.created_at.desc())).all())

def get_assessment(db: Session, assessment_id):
    return db.get(ControlRiskAssessment, assessment_id)

def list_contributions(db: Session, assessment_id):
    return list(db.scalars(
        select(ControlRiskContribution).where(ControlRiskContribution.assessment_id == assessment_id)
    ).all())
