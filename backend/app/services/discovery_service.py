from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.discovery import (
    DiscoveryEvidence,
    DiscoveryJob,
    DiscoveredHost,
)
from app.models.security_lab import (
    Asset,
    Network,
    ScanScope,
)
from app.services.discovery_reconciliation import (
    apply_observation,
    reconcile_host,
)
from app.services.discovery_scope import validate_discovery_target
from app.services.nmap_runner import run_nmap_discovery
from app.services.nmap_xml_parser import parse_nmap_xml


DiscoveryMethod = Literal["icmp", "arp", "tcp"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _approved_scopes(
    db: Session,
) -> list[ScanScope]:
    """
    Return enabled ScanScopes that belong to networks explicitly
    approved for scanning.
    """
    return list(
        db.scalars(
            select(ScanScope)
            .join(
                Network,
                ScanScope.network_id == Network.id,
            )
            .where(
                ScanScope.enabled.is_(True),
                Network.approved_for_scanning.is_(True),
            )
        ).all()
    )


def _assets_in_target(
    db: Session,
    target: str,
) -> list[Asset]:
    """
    Return manually managed assets contained inside the requested
    host or network target.
    """
    if "/" in target:
        requested = ipaddress.ip_network(
            target,
            strict=False,
        )
    else:
        address = ipaddress.ip_address(target)

        requested = ipaddress.ip_network(
            f"{address}/{address.max_prefixlen}",
            strict=False,
        )

    all_assets = list(
        db.scalars(
            select(Asset)
        ).all()
    )

    result: list[Asset] = []

    for asset in all_assets:
        try:
            asset_ip = ipaddress.ip_address(
                asset.ip_address
            )

            if asset_ip in requested:
                result.append(asset)

        except ValueError:
            # Ignore malformed historical asset addresses rather than
            # allowing them to break discovery reconciliation.
            continue

    return result


def _validate_method(
    method: str,
) -> DiscoveryMethod:
    """
    Defense-in-depth validation.

    Pydantic already validates the API request, but the service may
    also be invoked internally, so validation is repeated here.
    """
    normalized = method.strip().lower()

    if normalized not in {
        "icmp",
        "arp",
        "tcp",
    }:
        raise ValueError(
            "Unsupported discovery method. "
            "Expected one of: icmp, arp, tcp."
        )

    return normalized  # type: ignore[return-value]


def execute_discovery(
    db: Session,
    *,
    target: str,
    method: str,
    explicitly_authorized: bool,
    timeout_seconds: int = 300,
) -> tuple[DiscoveryJob, list[DiscoveredHost]]:
    """
    Execute one authorized network asset discovery operation.

    Processing order:

    1. Validate requested discovery method.
    2. Validate complete target against approved ScanScope.
    3. Create DiscoveryJob.
    4. Execute Nmap discovery.
    5. Preserve raw XML evidence.
    6. Parse Nmap XML.
    7. Reconcile observations against manually managed assets.
    8. Record discovered/missing/change observations.
    9. Mark the DiscoveryJob completed.

    Nmap is never executed before ScanScope authorization succeeds.
    """

    normalized_method = _validate_method(
        method
    )

    decision = validate_discovery_target(
        target,
        _approved_scopes(db),
        explicitly_authorized=explicitly_authorized,
    )

    if (
        not decision.allowed
        or decision.normalized_target is None
    ):
        raise PermissionError(
            decision.reason
        )

    job = DiscoveryJob(
        target=decision.normalized_target,
        discovery_method=normalized_method,
        scan_source="nmap",
        status="running",
        explicitly_authorized=explicitly_authorized,
        started_at=_utcnow(),
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        # IMPORTANT:
        # Pass through the exact normalized method selected by the user.
        #
        # arp  -> Nmap -PR
        # icmp -> Nmap -PE -PP -PM
        # tcp  -> Nmap -PS / -PA
        execution = run_nmap_discovery(
            decision.normalized_target,
            normalized_method,
            timeout_seconds=timeout_seconds,
        )

        job.command_args_json = json.dumps(
            execution.command
        )

        # Preserve the original scanner evidence before parsing or
        # normalization. If parsing/reconciliation later fails, the
        # original Nmap XML remains available for investigation.
        evidence = DiscoveryEvidence(
            discovery_job_id=job.id,
            evidence_type="nmap_xml",
            content_sha256=hashlib.sha256(
                execution.xml_text.encode(
                    "utf-8"
                )
            ).hexdigest(),
            raw_xml=execution.xml_text,
            captured_at=_utcnow(),
        )

        db.add(evidence)
        db.commit()
        db.refresh(job)

        scan_timestamp, parsed_hosts = parse_nmap_xml(
            execution.xml_text
        )

        target_assets = _assets_in_target(
            db,
            decision.normalized_target,
        )

        observed_asset_ids: set = set()

        rows: list[DiscoveredHost] = []

        for host in parsed_hosts:
            reconciliation = reconcile_host(
                host,
                target_assets,
            )

            asset = reconciliation.asset

            changes = list(
                reconciliation.changes
            )

            if asset is None:
                # Unknown observations remain discovery observations.
                # They are NOT automatically promoted to manually
                # managed Asset records.
                first_seen = scan_timestamp

            else:
                observed_asset_ids.add(
                    asset.id
                )

                first_seen = (
                    asset.first_seen
                    or scan_timestamp
                )

                apply_observation(
                    asset,
                    host,
                    scan_timestamp,
                    "nmap",
                )

            row = DiscoveredHost(
                discovery_job_id=job.id,
                matched_asset_id=(
                    asset.id
                    if asset
                    else None
                ),
                ip_address=host.ip_address,
                hostname=host.hostname,
                mac_address=host.mac_address,
                vendor=host.vendor,
                reachable=host.reachable,
                state=host.state,
                first_seen=first_seen,
                last_seen=scan_timestamp,
                scan_source="nmap",
                scan_timestamp=scan_timestamp,
                identity_basis=(
                    reconciliation.identity_basis
                ),
                change_types=(
                    ",".join(changes)
                    if changes
                    else None
                ),
            )

            db.add(row)
            rows.append(row)

        # Manual assets inside the scanned scope that were not observed
        # are explicitly represented as missing observations.
        #
        # The Asset itself is preserved; it is not deleted.
        for asset in target_assets:
            if asset.id in observed_asset_ids:
                continue

            asset.reachable = False

            row = DiscoveredHost(
                discovery_job_id=job.id,
                matched_asset_id=asset.id,
                ip_address=asset.ip_address,
                hostname=asset.hostname,
                mac_address=asset.mac_address,
                vendor=asset.vendor,
                reachable=False,
                state="missing",
                first_seen=(
                    asset.first_seen
                    or asset.created_at
                ),
                last_seen=(
                    asset.last_seen
                    or asset.created_at
                ),
                scan_source="nmap",
                scan_timestamp=scan_timestamp,
                identity_basis="manual_asset_identity",
                change_types="missing_asset",
            )

            db.add(row)
            rows.append(row)

        job.status = "completed"
        job.completed_at = _utcnow()

        db.commit()

        for row in rows:
            db.refresh(row)

        db.refresh(job)

        return job, rows

    except Exception as exc:
        db.rollback()

        # The job was committed before Nmap execution. Re-load it and
        # persist failure information without losing the historical job.
        failed = db.get(
            DiscoveryJob,
            job.id,
        )

        if failed is not None:
            failed.status = "failed"
            failed.error_message = str(exc)
            failed.completed_at = _utcnow()

            db.commit()

        raise