from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.security_lab import Asset
from app.models.web_assessment import WebAssessmentImport, WebEvidence, WebFinding
from app.services.web_deduplication import build_dedupe_key
from app.services.web_finding_classifier import classify
from app.services.web_scanner_parsers import parse_scanner


def import_web_assessment(
    db: Session,
    *,
    asset_id,
    target_url: str,
    scanner: str,
    source_name: str,
    payload,
):
    if asset_id is not None and db.get(Asset, asset_id) is None:
        raise ValueError("Asset not found.")

    run = WebAssessmentImport(
        asset_id=asset_id,
        target_url=target_url,
        scanner=scanner,
        source_name=source_name,
        status="running",
        evidence_count=0,
        finding_count=0,
        duplicate_count=0,
    )
    db.add(run)
    db.flush()

    parsed = parse_scanner(scanner, payload)
    findings: list[WebFinding] = []
    duplicates = 0
    evidence_count = 0

    for item in parsed:
        dedupe_key = build_dedupe_key(
            url=item["url"],
            method=item.get("method"),
            title=item["title"],
            finding_type=None,
            parameter=item.get("parameter"),
        )

        existing = db.scalar(select(WebEvidence).where(WebEvidence.dedupe_key == dedupe_key))
        if existing is not None:
            duplicates += 1
            continue

        evidence = WebEvidence(
            import_id=run.id,
            scanner=item["scanner"],
            rule_id=item.get("rule_id"),
            title=item["title"],
            severity=item["severity"],
            method=item.get("method"),
            url=item["url"],
            parameter=item.get("parameter"),
            request_metadata=item.get("request_metadata") or {},
            response_metadata=item.get("response_metadata") or {},
            evidence_text=item.get("evidence_text"),
            raw_redacted=item.get("raw_redacted") or {},
            dedupe_key=dedupe_key,
        )
        db.add(evidence)
        db.flush()
        evidence_count += 1

        classified = classify(
            item["title"],
            item.get("evidence_text"),
            item["severity"],
            item["scanner"],
        )
        if classified is None:
            continue

        finding = WebFinding(
            import_id=run.id,
            evidence_id=evidence.id,
            finding_type=classified.finding_type,
            title=classified.title,
            severity=classified.severity,
            confidence=classified.confidence,
            description=classified.description,
            remediation=classified.remediation,
            owasp_top10=classified.owasp_top10,
            mapping_rationale=classified.mapping_rationale,
        )
        db.add(finding)
        findings.append(finding)

    run.status = "completed"
    run.evidence_count = evidence_count
    run.finding_count = len(findings)
    run.duplicate_count = duplicates

    db.commit()
    db.refresh(run)
    for finding in findings:
        db.refresh(finding)

    return run, findings, duplicates


def list_imports(db: Session):
    return list(
        db.scalars(
            select(WebAssessmentImport).order_by(WebAssessmentImport.imported_at.desc())
        ).all()
    )


def list_findings(db: Session, import_id):
    return list(
        db.scalars(
            select(WebFinding)
            .where(WebFinding.import_id == import_id)
            .order_by(WebFinding.created_at.asc())
        ).all()
    )


def list_evidence(db: Session, import_id):
    return list(
        db.scalars(
            select(WebEvidence)
            .where(WebEvidence.import_id == import_id)
            .order_by(WebEvidence.created_at.asc())
        ).all()
    )
