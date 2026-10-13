from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.config_assessment import (
    BenchmarkProfile,
    ConfigAssessmentRun,
    ConfigEvidence,
    ConfigurationFinding,
)
from app.models.security_lab import Asset
from app.services.config_benchmark_catalog import BENCHMARK_PROFILES
from app.services.config_rules import evaluate_control


def ensure_benchmark_profiles(db: Session) -> list[BenchmarkProfile]:
    rows: list[BenchmarkProfile] = []
    changed = False
    for name, item in BENCHMARK_PROFILES.items():
        row = db.scalar(select(BenchmarkProfile).where(BenchmarkProfile.name == name))
        if row is None:
            row = BenchmarkProfile(
                name=name,
                platform=item["platform"],
                description=item["description"],
                controls=item["controls"],
            )
            db.add(row)
            db.flush()
            changed = True
        else:
            if (
                row.platform != item["platform"]
                or row.description != item["description"]
                or row.controls != item["controls"]
            ):
                row.platform = item["platform"]
                row.description = item["description"]
                row.controls = item["controls"]
                changed = True
        rows.append(row)
    if changed:
        db.commit()
        for row in rows:
            db.refresh(row)
    return rows


def run_assessment(
    db: Session,
    *,
    asset_id,
    profile_name: str,
    source_type: str,
    source_name: str,
    evidence_items: list[dict],
):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise ValueError("Asset not found.")

    ensure_benchmark_profiles(db)
    profile = db.scalar(select(BenchmarkProfile).where(BenchmarkProfile.name == profile_name))
    if profile is None:
        raise ValueError(f"Unknown benchmark profile: {profile_name}")

    run = ConfigAssessmentRun(
        asset_id=asset_id,
        profile_id=profile.id,
        source_type=source_type,
        source_name=source_name,
        status="running",
        evidence_count=0,
        finding_count=0,
    )
    db.add(run)
    db.flush()

    findings: list[ConfigurationFinding] = []
    evidence_count = 0

    for item in evidence_items:
        control_id = item.get("control_id")
        row = ConfigEvidence(
            assessment_id=run.id,
            control_id=control_id,
            category=item["category"],
            observed_value=item["observed_value"],
            source_locator=item.get("source_locator"),
            confidence=item.get("confidence", "high confidence"),
            raw_json=item.get("raw") or {},
        )
        db.add(row)
        evidence_count += 1

        if not control_id:
            continue

        if control_id not in profile.controls:
            continue

        result = evaluate_control(
            control_id,
            item["observed_value"],
            item.get("raw") or {},
            item.get("confidence", "high confidence"),
        )
        if result is None:
            continue

        finding = ConfigurationFinding(
            assessment_id=run.id,
            control=result.control,
            expected_state=result.expected_state,
            observed_state=result.observed_state,
            evidence={
                "control_id": control_id,
                "category": item["category"],
                "source_locator": item.get("source_locator"),
                "raw": item.get("raw") or {},
            },
            severity=result.severity,
            remediation=result.remediation,
            confidence=result.confidence,
            framework_reference=result.framework_reference,
        )
        db.add(finding)
        findings.append(finding)

    run.status = "completed"
    run.evidence_count = evidence_count
    run.finding_count = len(findings)

    db.commit()
    db.refresh(run)
    for finding in findings:
        db.refresh(finding)

    return run, findings


def list_findings(db: Session, assessment_id):
    return list(
        db.scalars(
            select(ConfigurationFinding)
            .where(ConfigurationFinding.assessment_id == assessment_id)
            .order_by(ConfigurationFinding.created_at.asc())
        ).all()
    )


def list_evidence(db: Session, assessment_id):
    return list(
        db.scalars(
            select(ConfigEvidence)
            .where(ConfigEvidence.assessment_id == assessment_id)
            .order_by(ConfigEvidence.created_at.asc())
        ).all()
    )
