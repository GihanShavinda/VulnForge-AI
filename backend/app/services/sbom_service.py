from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.sbom import (
    ComponentDriftEvent,
    PackageComponent,
    PackageVulnerabilityMatch,
    SbomImport,
    VulnerabilityAdvisory,
)
from app.models.security_lab import Asset
from app.services.component_drift import detect_component_drift
from app.services.package_vulnerability_matcher import AdvisoryCandidate, evaluate_advisory
from app.services.sbom_identity import component_fingerprint, component_identity_key
from app.services.sbom_parsers import canonical_payload, parse_sbom
from app.services.sbom_types import DirectVulnerabilityFinding, NormalizedComponent


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _component_from_row(row: PackageComponent) -> NormalizedComponent:
    return NormalizedComponent(
        name=row.name,
        version=row.version,
        ecosystem=row.ecosystem,
        purl=row.purl,
        cpe=row.cpe,
        supplier=row.supplier,
        package_origin=row.package_origin,
        source=row.source,
        vendor_status=row.vendor_status,
        evidence=row.evidence_json or {},
    )


def _latest_previous_import(db: Session, asset_id, current_import_id):
    return db.scalar(
        select(SbomImport)
        .where(
            SbomImport.asset_id == asset_id,
            SbomImport.id != current_import_id,
            SbomImport.status == "completed",
        )
        .order_by(SbomImport.imported_at.desc())
        .limit(1)
    )


def _find_component_for_direct_finding(
    finding: DirectVulnerabilityFinding,
    components: list[tuple[PackageComponent, NormalizedComponent]],
) -> PackageComponent | None:
    if finding.component_ref:
        for row, normalized in components:
            if normalized.source_ref == finding.component_ref:
                return row

    if finding.purl:
        for row, normalized in components:
            if normalized.purl == finding.purl and (
                not finding.installed_version or normalized.version == finding.installed_version
            ):
                return row

    if finding.package_name and finding.ecosystem:
        wanted_name = finding.package_name.strip().lower()
        wanted_eco = finding.ecosystem.strip().lower()
        candidates = [
            row
            for row, normalized in components
            if normalized.name.strip().lower() == wanted_name
            and (normalized.ecosystem or "").strip().lower() == wanted_eco
            and (not finding.installed_version or normalized.version == finding.installed_version)
        ]
        if len(candidates) == 1:
            return candidates[0]

    return None


def import_sbom(
    db: Session,
    *,
    asset_id,
    fmt: str,
    source_name: str,
    document,
    raw_text: str | None,
):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise ValueError("Asset not found.")

    raw_payload = canonical_payload(document, raw_text)
    source_sha = hashlib.sha256(raw_payload).hexdigest()
    normalized_components, direct_findings = parse_sbom(fmt, document, raw_text)

    sbom = SbomImport(
        asset_id=asset.id,
        format=fmt.strip().lower(),
        source_name=source_name,
        source_sha256=source_sha,
        status="completed",
        component_count=0,
        vulnerability_count=0,
        imported_at=utcnow(),
    )
    db.add(sbom)
    db.flush()

    component_rows: list[tuple[PackageComponent, NormalizedComponent]] = []
    for item in normalized_components:
        row = PackageComponent(
            sbom_import_id=sbom.id,
            asset_id=asset.id,
            name=item.name,
            version=item.version,
            ecosystem=item.ecosystem,
            purl=item.purl,
            cpe=item.cpe,
            supplier=item.supplier,
            package_origin=item.package_origin,
            source=item.source,
            vendor_status=item.vendor_status,
            evidence_json=item.evidence,
            identity_key=component_identity_key(item),
            fingerprint_sha256=component_fingerprint(item),
            created_at=utcnow(),
        )
        db.add(row)
        db.flush()
        component_rows.append((row, item))

    match_rows: list[PackageVulnerabilityMatch] = []

    for finding in direct_findings:
        component_row = _find_component_for_direct_finding(finding, component_rows)
        if component_row is None:
            continue

        row = PackageVulnerabilityMatch(
            sbom_import_id=sbom.id,
            component_id=component_row.id,
            advisory_id=None,
            vulnerability_id=finding.vulnerability_id,
            match_source=finding.source,
            match_method="scanner_assertion",
            version_evidence=(
                f"Scanner/SBOM source reported installed version "
                f"{finding.installed_version or component_row.version or 'unknown'}."
            ),
            confidence=finding.confidence,
            fixed_version=finding.fixed_version,
            affected_range=finding.affected_range,
            package_origin=component_row.package_origin,
            evidence_json=finding.evidence,
            created_at=utcnow(),
        )
        db.add(row)
        match_rows.append(row)

    advisories = list(db.scalars(select(VulnerabilityAdvisory)).all())

    for component_row, normalized in component_rows:
        for advisory in advisories:
            candidate = AdvisoryCandidate(
                vulnerability_id=advisory.vulnerability_id,
                source=advisory.source,
                ecosystem=advisory.ecosystem,
                package_name=advisory.package_name,
                purl=advisory.purl,
                cpe=advisory.cpe,
                affected_range=advisory.affected_range,
                fixed_version=advisory.fixed_version,
                version_scheme=advisory.version_scheme,
                confidence=advisory.confidence,
                evidence=advisory.evidence_json,
                advisory_id=advisory.id,
            )
            decision = evaluate_advisory(normalized, candidate)
            if not decision.matched:
                continue

            if any(
                x.component_id == component_row.id
                and x.vulnerability_id == advisory.vulnerability_id
                and x.match_source == advisory.source
                for x in match_rows
            ):
                continue

            row = PackageVulnerabilityMatch(
                sbom_import_id=sbom.id,
                component_id=component_row.id,
                advisory_id=advisory.id,
                vulnerability_id=advisory.vulnerability_id,
                match_source=advisory.source,
                match_method=decision.method or "unknown",
                version_evidence=decision.version_evidence,
                confidence=decision.confidence,
                fixed_version=advisory.fixed_version,
                affected_range=advisory.affected_range,
                package_origin=component_row.package_origin,
                evidence_json={
                    "match_reason": decision.reason,
                    "advisory_evidence": advisory.evidence_json,
                },
                created_at=utcnow(),
            )
            db.add(row)
            match_rows.append(row)

    previous_import = _latest_previous_import(db, asset.id, sbom.id)
    drift_rows: list[ComponentDriftEvent] = []

    if previous_import:
        previous_rows = list(
            db.scalars(
                select(PackageComponent).where(
                    PackageComponent.sbom_import_id == previous_import.id
                )
            ).all()
        )
        previous_components = [_component_from_row(x) for x in previous_rows]
        drift = detect_component_drift(previous_components, normalized_components)

        for event in drift:
            row = ComponentDriftEvent(
                asset_id=asset.id,
                previous_import_id=previous_import.id,
                current_import_id=sbom.id,
                identity_key=event.identity_key,
                change_type=event.change_type,
                previous_version=event.previous_version,
                current_version=event.current_version,
                evidence_json={
                    "previous_import": str(previous_import.id),
                    "current_import": str(sbom.id),
                },
                created_at=utcnow(),
            )
            db.add(row)
            drift_rows.append(row)

    sbom.component_count = len(component_rows)
    sbom.vulnerability_count = len(match_rows)

    db.commit()
    db.refresh(sbom)

    for row, _ in component_rows:
        db.refresh(row)
    for row in match_rows:
        db.refresh(row)
    for row in drift_rows:
        db.refresh(row)

    return sbom, [row for row, _ in component_rows], match_rows, drift_rows
