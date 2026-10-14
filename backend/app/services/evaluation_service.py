from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evaluation import EvaluationFinding, EvaluationRun
from app.services.evaluation_engine import calculate_evaluation


def create_evaluation(db: Session, payload):
    rows = [item.model_dump() for item in payload.findings]
    table, metrics = calculate_evaluation(rows, payload.top_k)

    run = EvaluationRun(
        environment_name=payload.environment_name,
        dataset_name=payload.dataset_name,
        notes=payload.notes,
        experiment_table=table,
        metrics=metrics,
    )
    db.add(run)
    db.flush()

    for item in rows:
        db.add(
            EvaluationFinding(
                evaluation_run_id=run.id,
                finding_ref=item["finding_ref"],
                cvss_score=item["cvss_score"],
                kev=int(item["kev"]),
                epss=item["epss"],
                environmental_score=item["environmental_score"],
                expert_rank=item["expert_rank"],
                predicted_applicable=int(item["predicted_applicable"]),
                applicable=int(item["applicable"]),
                attack_path_relevant=int(item["attack_path_relevant"]),
                triage_seconds=item["triage_seconds"],
                pre_remediation_risk=item["pre_remediation_risk"],
                post_remediation_risk=item["post_remediation_risk"],
                ai_factual_correct=int(item["ai_factual_correct"]),
                ai_unsupported_claim=int(item["ai_unsupported_claim"]),
                security_rule_correct=int(item["security_rule_correct"]),
                verification_success=int(item["verification_success"]),
            )
        )

    db.commit()
    db.refresh(run)
    return run


def list_evaluations(db: Session):
    return list(
        db.scalars(
            select(EvaluationRun)
            .order_by(EvaluationRun.created_at.desc())
        ).all()
    )


def get_evaluation(db: Session, run_id):
    return db.get(EvaluationRun, run_id)
