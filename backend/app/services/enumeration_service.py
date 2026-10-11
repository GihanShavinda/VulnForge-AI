from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enumeration import (
    EnumerationEvidence,
    EnumerationJob,
    ExposureFinding,
    ServiceObservation,
)
from app.models.security_lab import Asset, Network, ScanScope
from app.services.discovery_scope import validate_discovery_target
from app.services.exposure_rules import evaluate_exposure_rules
from app.services.nmap_service_runner import run_nmap_service_enumeration
from app.services.nmap_service_xml_parser import parse_nmap_service_xml, scripts_as_json
from app.services.service_change_detection import (
    ComparableService,
    detect_current_changes,
    index_by_port,
    previously_open_now_missing,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _approved_scopes(db: Session) -> list[ScanScope]:
    return list(
        db.scalars(
            select(ScanScope)
            .join(Network, ScanScope.network_id == Network.id)
            .where(ScanScope.enabled.is_(True), Network.approved_for_scanning.is_(True))
        ).all()
    )


def _latest_previous_job(db: Session, asset_id, protocol: str, top_ports: int) -> EnumerationJob | None:
    return db.scalar(
        select(EnumerationJob)
        .where(
            EnumerationJob.asset_id == asset_id,
            EnumerationJob.protocol == protocol,
            EnumerationJob.top_ports == top_ports,
            EnumerationJob.status == "completed",
        )
        .order_by(EnumerationJob.completed_at.desc().nullslast(), EnumerationJob.created_at.desc())
        .limit(1)
    )


def execute_service_enumeration(
    db: Session,
    *,
    asset_id,
    protocol: str,
    top_ports: int,
    explicitly_authorized: bool,
    timeout_seconds: int = 900,
) -> tuple[EnumerationJob, list[ServiceObservation], list[ExposureFinding]]:
    protocol = protocol.strip().lower()
    if protocol not in {"tcp", "udp"}:
        raise ValueError("protocol must be 'tcp' or 'udp'.")

    asset = db.get(Asset, asset_id)
    if asset is None:
        raise ValueError("Asset not found.")
    if not asset.scanning_enabled:
        raise PermissionError("Asset scanning is disabled.")

    decision = validate_discovery_target(
        asset.ip_address,
        _approved_scopes(db),
        explicitly_authorized=explicitly_authorized,
    )
    if not decision.allowed or decision.normalized_target is None:
        raise PermissionError(decision.reason)

    previous_job = _latest_previous_job(db, asset.id, protocol, top_ports)
    previous_rows = []
    if previous_job is not None:
        previous_rows = list(
            db.scalars(
                select(ServiceObservation).where(
                    ServiceObservation.enumeration_job_id == previous_job.id
                )
            ).all()
        )

    job = EnumerationJob(
        asset_id=asset.id,
        target=decision.normalized_target,
        protocol=protocol,
        top_ports=top_ports,
        scan_source="nmap",
        status="running",
        explicitly_authorized=explicitly_authorized,
        started_at=_utcnow(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        execution = run_nmap_service_enumeration(
            decision.normalized_target,
            protocol,
            top_ports,
            timeout_seconds=timeout_seconds,
        )
        job.command_args_json = json.dumps(execution.command)

        evidence = EnumerationEvidence(
            enumeration_job_id=job.id,
            evidence_type="nmap_xml",
            content_sha256=hashlib.sha256(execution.xml_text.encode("utf-8")).hexdigest(),
            raw_xml=execution.xml_text,
            captured_at=_utcnow(),
        )
        db.add(evidence)
        db.commit()

        scan_timestamp, parsed = parse_nmap_service_xml(execution.xml_text)

        prev_comparable = [
            ComparableService(x.port, x.protocol, x.state, x.service, x.version)
            for x in previous_rows
        ]
        prev_by_endpoint = {(x.port, x.protocol): x for x in prev_comparable}
        prev_by_port = index_by_port(prev_comparable)

        current_comparable = [
            ComparableService(x.port, x.protocol, x.state, x.service, x.version)
            for x in parsed
        ]

        rows: list[ServiceObservation] = []
        findings: list[ExposureFinding] = []

        for item in parsed:
            current = ComparableService(item.port, item.protocol, item.state, item.service, item.version)
            previous = prev_by_endpoint.get((item.port, item.protocol))
            changes = detect_current_changes(current, previous, prev_by_port.get(item.port, []))

            first_seen = scan_timestamp
            if previous is not None:
                previous_row = next(
                    (x for x in previous_rows if x.port == item.port and x.protocol == item.protocol),
                    None,
                )
                if previous_row is not None:
                    first_seen = previous_row.first_seen

            row = ServiceObservation(
                enumeration_job_id=job.id,
                asset_id=asset.id,
                ip_address=item.ip_address,
                port=item.port,
                protocol=item.protocol,
                state=item.state,
                service=item.service,
                product=item.product,
                version=item.version,
                banner=item.banner,
                cpe=item.cpe,
                tls_indicator=item.tls_indicator,
                scan_confidence=item.scan_confidence,
                detection_source=item.detection_source,
                script_outputs_json=scripts_as_json(item),
                first_seen=first_seen,
                last_seen=scan_timestamp,
                change_types=",".join(changes) if changes else None,
            )
            db.add(row)
            db.flush()
            rows.append(row)

            for candidate in evaluate_exposure_rules(
                port=item.port,
                protocol=item.protocol,
                state=item.state,
                service=item.service,
                product=item.product,
                version=item.version,
                banner=item.banner,
                tls_indicator=item.tls_indicator,
                scripts=item.script_outputs,
                asset_role=asset.role,
            ):
                finding = ExposureFinding(
                    enumeration_job_id=job.id,
                    service_observation_id=row.id,
                    asset_id=asset.id,
                    rule_code=candidate.rule_code,
                    title=candidate.title,
                    category=candidate.category,
                    severity=candidate.severity,
                    conclusion=candidate.conclusion,
                    evidence_json=json.dumps({
                        "nmap_evidence_sha256": evidence.content_sha256,
                        "service_observation": candidate.evidence,
                    }, sort_keys=True),
                )
                db.add(finding)
                findings.append(finding)

        # If a previously-open endpoint is absent from the new completed scan,
        # record a synthetic closed observation so the change is explicit.
        for old in previously_open_now_missing(prev_comparable, current_comparable):
            previous_row = next(
                x for x in previous_rows if x.port == old.port and x.protocol == old.protocol
            )
            row = ServiceObservation(
                enumeration_job_id=job.id,
                asset_id=asset.id,
                ip_address=asset.ip_address,
                port=old.port,
                protocol=old.protocol,
                state="closed",
                service=old.service,
                product=previous_row.product,
                version=old.version,
                banner=None,
                cpe=previous_row.cpe,
                tls_indicator=previous_row.tls_indicator,
                scan_confidence=None,
                detection_source="vulnforge-scan-diff",
                script_outputs_json=None,
                first_seen=previous_row.first_seen,
                last_seen=scan_timestamp,
                change_types="closed_port",
            )
            db.add(row)
            rows.append(row)

        job.status = "completed"
        job.completed_at = _utcnow()
        db.commit()

        for row in rows:
            db.refresh(row)
        for finding in findings:
            db.refresh(finding)
        db.refresh(job)
        return job, rows, findings

    except Exception as exc:
        db.rollback()
        failed = db.get(EnumerationJob, job.id)
        if failed is not None:
            failed.status = "failed"
            failed.error_message = str(exc)
            failed.completed_at = _utcnow()
            db.commit()
        raise
