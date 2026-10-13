from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.authenticated_assessment import (
    AuthenticatedEvidence,
    AuthenticatedScan,
)
from app.models.enumeration import (
    EnumerationJob,
    ServiceObservation,
)
from app.models.fingerprinting import (
    FingerprintJob,
    TechnologyObservation,
)


RANK = {
    "unknown": 0,
    "low confidence": 1,
    "medium confidence": 2,
    "high confidence": 3,
    "confirmed": 4,
}


def _latest_fingerprint(
    db: Session,
    asset_id,
):
    """
    Return the latest preferred operating-system fingerprint observation
    for the asset.
    """

    job = db.scalar(
        select(FingerprintJob)
        .where(
            FingerprintJob.asset_id == asset_id,
            FingerprintJob.status.in_(
                [
                    "completed",
                    "completed_with_warnings",
                ]
            ),
        )
        .order_by(
            FingerprintJob.completed_at.desc().nullslast(),
        )
        .limit(1)
    )

    if not job:
        return None

    return db.scalar(
        select(TechnologyObservation)
        .where(
            TechnologyObservation.fingerprint_job_id == job.id,
            TechnologyObservation.is_preferred.is_(True),
            TechnologyObservation.observed_name.in_(
                [
                    "Windows XP",
                    "Windows 7",
                    "Windows 10",
                    "Ubuntu",
                    "Linux",
                ]
            ),
        )
        .limit(1)
    )


def _latest_services(
    db: Session,
    asset_id,
) -> set[tuple[str, int]]:
    """
    Return the open services from the latest completed unauthenticated
    service-enumeration job.
    """

    job = db.scalar(
        select(EnumerationJob)
        .where(
            EnumerationJob.asset_id == asset_id,
            EnumerationJob.status == "completed",
        )
        .order_by(
            EnumerationJob.completed_at.desc().nullslast(),
        )
        .limit(1)
    )

    if not job:
        return set()

    observations = db.scalars(
        select(ServiceObservation).where(
            ServiceObservation.enumeration_job_id == job.id,
            ServiceObservation.state == "open",
        )
    ).all()

    return {
        (
            observation.protocol.lower(),
            observation.port,
        )
        for observation in observations
    }


def _valid_port(
    value: str,
) -> int | None:
    """
    Convert a candidate string to a valid TCP/UDP port number.
    """

    try:
        port = int(value)
    except (TypeError, ValueError):
        return None

    if 1 <= port <= 65535:
        return port

    return None


def _port_from_endpoint(
    endpoint: str,
) -> int | None:
    """
    Extract a port from a network endpoint.

    Supported examples:

        0.0.0.0:22
        127.0.0.1:5432
        192.168.37.20:22
        [::]:22
        [::1]:5432
        :::22
        *:53
    """

    value = endpoint.strip()

    match = re.search(
        r":(\d{1,5})$",
        value,
    )

    if not match:
        return None

    return _valid_port(
        match.group(1)
    )


def _ports(
    text: str,
) -> set[tuple[str, int]]:
    """
    Extract TCP/UDP listening ports from authenticated host evidence.

    Supported evidence formats include:

    Linux ss:
        tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
        udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*

    Linux/other compact formats:
        22/tcp
        53/udp
        tcp:22
        udp:53
        tcp 22

    Windows netstat:
        TCP    0.0.0.0:135    0.0.0.0:0    LISTENING
        TCP    [::]:445       [::]:0       LISTENING
        UDP    0.0.0.0:53     *:*

    The first endpoint token in an ss/netstat line is treated as the local
    endpoint. Peer/remote ports are deliberately ignored.
    """

    found: set[tuple[str, int]] = set()

    if not text:
        return found

    # ---------------------------------------------------------------------
    # Explicit "22/tcp" or "53/udp" form.
    # ---------------------------------------------------------------------
    for match in re.finditer(
        r"(?i)\b(\d{1,5})/(tcp|udp)\b",
        text,
    ):
        port = _valid_port(
            match.group(1)
        )

        if port is None:
            continue

        protocol = match.group(2).lower()

        found.add(
            (
                protocol,
                port,
            )
        )

    # ---------------------------------------------------------------------
    # Explicit compact forms:
    #
    # tcp:22
    # udp:53
    # tcp 22
    #
    # Keep this deliberately narrow so numbers in ss queue fields are not
    # accidentally interpreted as ports.
    # ---------------------------------------------------------------------
    for match in re.finditer(
        r"(?im)\b(tcp|udp)\b\s*[:=]\s*(\d{1,5})\b",
        text,
    ):
        protocol = match.group(1).lower()

        port = _valid_port(
            match.group(2)
        )

        if port is not None:
            found.add(
                (
                    protocol,
                    port,
                )
            )

    # ---------------------------------------------------------------------
    # Parse line-oriented Linux ss / Windows netstat output.
    #
    # Linux:
    # tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
    #
    # Windows:
    # TCP 0.0.0.0:135 0.0.0.0:0 LISTENING 720
    #
    # Starting after the protocol token, locate the first token that looks
    # like an endpoint ending in a numeric port. That is the local endpoint.
    # ---------------------------------------------------------------------
    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        tokens = line.split()

        if not tokens:
            continue

        protocol = tokens[0].lower()

        if protocol not in {
            "tcp",
            "udp",
        }:
            continue

        local_port: int | None = None

        for token in tokens[1:]:
            port = _port_from_endpoint(
                token
            )

            if port is None:
                continue

            local_port = port
            break

        if local_port is not None:
            found.add(
                (
                    protocol,
                    local_port,
                )
            )

    return found


def _first_evidence(
    evidence: list[AuthenticatedEvidence],
    categories: set[str],
) -> AuthenticatedEvidence | None:
    """
    Return the first evidence item whose normalized category is one of the
    requested categories.
    """

    normalized_categories = {
        category.strip().lower()
        for category in categories
    }

    for item in evidence:
        category = (
            item.category or ""
        ).strip().lower()

        if category in normalized_categories:
            return item

    return None


def build_comparison(
    db: Session,
    scan: AuthenticatedScan,
) -> list[dict]:
    """
    Compare unauthenticated V3/V4 observations with V5 authenticated
    evidence.

    Authenticated evidence does not overwrite historical unauthenticated
    observations. Instead, the comparison explains where direct host
    evidence increases confidence or reveals additional visibility.
    """

    evidence = list(
        db.scalars(
            select(
                AuthenticatedEvidence
            ).where(
                AuthenticatedEvidence.authenticated_scan_id
                == scan.id
            )
        ).all()
    )

    rows: list[dict] = []

    # =====================================================================
    # Operating-system comparison
    # =====================================================================

    unauth_os = _latest_fingerprint(
        db,
        scan.asset_id,
    )

    auth_os = _first_evidence(
        evidence,
        {
            # Linux SSH collector
            "os_release",

            # Windows imported evidence
            "windows_os_version",
            "os_version",

            # Compatibility alias
            "operating_system",
        },
    )

    if auth_os:
        old_confidence = (
            unauth_os.confidence
            if unauth_os
            else "unknown"
        )

        unauthenticated_value: str | None = None

        if unauth_os:
            unauthenticated_value = (
                unauth_os.observed_name
            )

            if unauth_os.observed_version:
                unauthenticated_value += (
                    f" {unauth_os.observed_version}"
                )

        rows.append(
            {
                "subject": "operating_system",
                "unauthenticated_value": (
                    unauthenticated_value
                ),
                "unauthenticated_confidence": (
                    old_confidence
                ),
                "authenticated_value": (
                    auth_os.observed_value[:1000]
                ),
                "authenticated_confidence": (
                    "confirmed"
                ),
                "confidence_increased": (
                    RANK["confirmed"]
                    > RANK.get(
                        old_confidence,
                        0,
                    )
                ),
                "note": (
                    "Authenticated host inventory is direct evidence "
                    "and can increase confidence without overwriting "
                    "the preserved unauthenticated observation."
                ),
            }
        )

    # =====================================================================
    # Listening-port comparison
    # =====================================================================

    unauth_ports = _latest_services(
        db,
        scan.asset_id,
    )

    auth_socket = _first_evidence(
        evidence,
        {
            # Linux SSH collection
            "listening_sockets",

            # Windows imported inventory
            "listening_ports",

            # Compatibility alias
            "listening_endpoints",
        },
    )

    if auth_socket:
        auth_ports = _ports(
            auth_socket.observed_value
        )

        extra_ports = sorted(
            auth_ports - unauth_ports
        )

        missing_from_authenticated = sorted(
            unauth_ports - auth_ports
        )

        rows.append(
            {
                "subject": (
                    "listening_ports_visibility"
                ),
                "unauthenticated_value": (
                    ", ".join(
                        f"{port}/{protocol}"
                        for protocol, port
                        in sorted(
                            unauth_ports
                        )
                    )
                    or None
                ),
                "unauthenticated_confidence": (
                    "high confidence"
                    if unauth_ports
                    else "unknown"
                ),
                "authenticated_value": (
                    ", ".join(
                        f"{port}/{protocol}"
                        for protocol, port
                        in sorted(
                            auth_ports
                        )
                    )
                    or None
                ),
                "authenticated_confidence": (
                    "confirmed"
                ),
                "confidence_increased": (
                    bool(auth_ports)
                    and not bool(unauth_ports)
                ),
                "note": (
                    "Authenticated collection saw "
                    f"{len(extra_ports)} listening endpoint(s) "
                    "not present in the latest unauthenticated "
                    "service view. "
                    f"{len(missing_from_authenticated)} "
                    "unauthenticated endpoint(s) were not present "
                    "in the authenticated listening-socket evidence."
                ),
            }
        )

    return rows