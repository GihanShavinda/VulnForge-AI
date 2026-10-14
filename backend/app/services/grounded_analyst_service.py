from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.grounded_analyst import GroundedAnalystAudit, GroundedAnalystRun
from app.services.grounded_analyst_fallback import deterministic_analysis
from app.services.grounding_policy import (
    untrusted_evidence,
    validate_output_grounding,
)

MODEL_NAME = "vulnforge-deterministic-grounded-fallback"


def analyze_and_store(db: Session, request):
    output = deterministic_analysis(request.evidence)
    validate_output_grounding(output, request.evidence)

    run = GroundedAnalystRun(
        calculation_version=request.calculation_version,
        model_name=MODEL_NAME,
        fallback_used=True,
        input_evidence=[item.model_dump(mode="json") for item in request.evidence],
        output_json=output.model_dump(mode="json"),
        grounding_status="validated",
    )
    db.add(run)
    db.flush()

    for item in untrusted_evidence(request.evidence):
        db.add(
            GroundedAnalystAudit(
                run_id=run.id,
                event_type="untrusted_data_contained",
                evidence_id=item.evidence_id,
                message=(
                    f"{item.evidence_type} retained as untrusted data; "
                    "not interpreted as instructions."
                ),
            )
        )

    db.add(
        GroundedAnalystAudit(
            run_id=run.id,
            event_type="grounding_validated",
            evidence_id=None,
            message="Every output statement references supplied evidence identifiers.",
        )
    )

    db.commit()
    db.refresh(run)
    return run, output


def list_runs(db: Session):
    return list(
        db.scalars(
            select(GroundedAnalystRun)
            .order_by(GroundedAnalystRun.created_at.desc())
        ).all()
    )


def get_run(db: Session, run_id):
    return db.get(GroundedAnalystRun, run_id)
