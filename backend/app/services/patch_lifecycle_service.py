from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.patch_lifecycle import (
    LifecycleFinding,
    PatchFinding,
    PatchLifecycleAssessmentRun,
)
from app.models.security_lab import Asset
from app.services.patch_lifecycle_rules import (
    classify_patch_state,
    lifecycle_severity,
)


def run_patch_lifecycle_assessment(
    db: Session,
    *,
    asset_id,
    source_name: str,
    patch_observations: list[dict],
    lifecycle_observations: list[dict],
):
    if asset_id is not None and db.get(Asset, asset_id) is None:
        raise ValueError("Asset not found.")

    run = PatchLifecycleAssessmentRun(
        asset_id=asset_id,
        source_name=source_name,
        status="running",
        patch_finding_count=0,
        lifecycle_finding_count=0,
    )
    db.add(run)
    db.flush()

    patch_findings: list[PatchFinding] = []
    lifecycle_findings: list[LifecycleFinding] = []

    for item in patch_observations:
        result = classify_patch_state(
            patch_available=item.get("patch_available"),
            vendor_backport=item.get("vendor_backport", False),
            compensating_control=item.get("compensating_control"),
        )
        finding = PatchFinding(
            run_id=run.id,
            component=item["component"],
            installed_version=item.get("installed_version"),
            fixed_version=item.get("fixed_version"),
            vulnerability_id=item.get("vulnerability_id"),
            severity=item.get("severity", "Medium"),
            risk_state=result.risk_state,
            patch_available=item.get("patch_available"),
            vendor_backport=item.get("vendor_backport", False),
            reboot_required=item.get("reboot_required"),
            compensating_control=item.get("compensating_control"),
            evidence=item.get("evidence") or {},
            remediation=result.remediation,
        )
        db.add(finding)
        patch_findings.append(finding)

    for item in lifecycle_observations:
        sev = lifecycle_severity(
            vendor_support_status=item["vendor_support_status"],
            accepted_legacy_system=item.get("accepted_legacy_system", False),
            temporary_compensating_control=item.get("temporary_compensating_control"),
        )
        finding = LifecycleFinding(
            run_id=run.id,
            product=item["product"],
            version=item.get("version"),
            category=item["category"],
            severity=sev,
            vendor_support_status=item["vendor_support_status"],
            end_of_support_date=item.get("end_of_support_date"),
            patch_availability=item["patch_availability"],
            accepted_legacy_system=item.get("accepted_legacy_system", False),
            temporary_compensating_control=item.get("temporary_compensating_control"),
            vendor_backport=item.get("vendor_backport", False),
            replacement_recommendation=item["replacement_recommendation"],
            evidence=item.get("evidence") or {},
        )
        db.add(finding)
        lifecycle_findings.append(finding)

    run.status = "completed"
    run.patch_finding_count = len(patch_findings)
    run.lifecycle_finding_count = len(lifecycle_findings)

    db.commit()
    db.refresh(run)
    for row in patch_findings + lifecycle_findings:
        db.refresh(row)

    return run, patch_findings, lifecycle_findings


def list_runs(db: Session):
    return list(
        db.scalars(
            select(PatchLifecycleAssessmentRun)
            .order_by(PatchLifecycleAssessmentRun.created_at.desc())
        ).all()
    )


def list_patch_findings(db: Session, run_id):
    return list(
        db.scalars(
            select(PatchFinding)
            .where(PatchFinding.run_id == run_id)
            .order_by(PatchFinding.first_seen.asc())
        ).all()
    )


def list_lifecycle_findings(db: Session, run_id):
    return list(
        db.scalars(
            select(LifecycleFinding)
            .where(LifecycleFinding.run_id == run_id)
            .order_by(LifecycleFinding.created_at.asc())
        ).all()
    )
