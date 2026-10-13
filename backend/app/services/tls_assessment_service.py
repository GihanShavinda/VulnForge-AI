from __future__ import annotations
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.security_lab import Asset
from app.models.tls_assessment import TLSAssessmentImport, TLSEvidence, CryptoFinding
from app.services.tls_rules import evaluate_tls_control

def run_tls_assessment(db: Session, *, asset_id, target: str, port: int, scanner: str, source_name: str, lab_context: bool, evidence_items: list[dict]):
    if asset_id is not None and db.get(Asset, asset_id) is None:
        raise ValueError("Asset not found.")

    run=TLSAssessmentImport(
        asset_id=asset_id,target=target,port=port,scanner=scanner,source_name=source_name,
        status="running",evidence_count=0,finding_count=0,lab_context=lab_context,
    )
    db.add(run); db.flush()
    findings=[]
    for item in evidence_items:
        ev=TLSEvidence(
            import_id=run.id,
            category=item["category"],
            observed_value=item["observed_value"],
            source_locator=item.get("source_locator"),
            confidence=item.get("confidence","high confidence"),
            raw_json=item.get("raw") or {},
        )
        db.add(ev)
        result=evaluate_tls_control(
            item["category"],item["observed_value"],
            confidence=item.get("confidence","high confidence"),
            lab_context=lab_context,
        )
        if result is not None:
            f=CryptoFinding(
                import_id=run.id,
                finding_type=result.finding_type,
                control=result.control,
                observed_state=result.observed_state,
                evidence={
                    "category":item["category"],
                    "source_locator":item.get("source_locator"),
                    "raw":item.get("raw") or {},
                },
                severity=result.severity,
                remediation=result.remediation,
                confidence=result.confidence,
                acceptable_lab_configuration=result.acceptable_lab_configuration,
                rationale=result.rationale,
            )
            db.add(f); findings.append(f)
    run.status="completed"
    run.evidence_count=len(evidence_items)
    run.finding_count=len(findings)
    db.commit(); db.refresh(run)
    for f in findings: db.refresh(f)
    return run, findings

def list_imports(db: Session):
    return list(db.scalars(select(TLSAssessmentImport).order_by(TLSAssessmentImport.imported_at.desc())).all())

def list_findings(db: Session, import_id):
    return list(db.scalars(select(CryptoFinding).where(CryptoFinding.import_id==import_id).order_by(CryptoFinding.created_at.asc())).all())

def list_evidence(db: Session, import_id):
    return list(db.scalars(select(TLSEvidence).where(TLSEvidence.import_id==import_id).order_by(TLSEvidence.created_at.asc())).all())
