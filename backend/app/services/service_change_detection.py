from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ComparableService:
    port: int
    protocol: str
    state: str
    service: str | None
    version: str | None


# Nmap service labels that represent uncertainty rather than a positively
# identified application protocol.
UNCERTAIN_SERVICES = {
    "",
    "unknown",
    "tcpwrapped",
}


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def _service_is_reliable(service: str | None) -> bool:
    """
    Return True only when Nmap positively identified a meaningful service.

    tcpwrapped is deliberately treated as uncertain because it normally means
    the remote endpoint accepted a TCP connection and then closed it before
    Nmap could complete service identification.
    """
    return _normalize(service) not in UNCERTAIN_SERVICES


def _version_is_reliable(version: str | None) -> bool:
    """
    Missing version information is not evidence that a version changed.
    """
    return bool((version or "").strip())


def detect_current_changes(
    current: ComparableService,
    previous_same_endpoint: ComparableService | None,
    previous_same_port: list[ComparableService],
) -> list[str]:
    """
    Compare a current service observation with the previous equivalent scan.

    Rules:

    new_port
        Previous endpoint was not open and the current endpoint is explicitly
        open.

    closed_port
        Previous endpoint was explicitly open and the current endpoint is
        explicitly CLOSED.

        IMPORTANT:
        filtered, open|filtered, unfiltered, and missing observations are NOT
        treated as closed.

    service_changed
        Both observations are open and both contain reliable service
        identification, but the service names differ.

        tcpwrapped / unknown / blank service names are not considered reliable
        enough to claim a service change.

    version_changed
        Both observations are open, represent the same reliable service, and
        both have explicit version strings that differ.

        Losing version metadata in a later scan is not enough to claim a
        version change.

    protocol_changed
        A newly observed open endpoint uses a different transport protocol for
        a port that was previously observed under another protocol.
    """

    changes: list[str] = []

    current_state = _normalize(current.state)

    # No previous observation for the same port/protocol.
    if previous_same_endpoint is None:
        if current_state == "open":
            changes.append("new_port")

        previous_open_other_protocol = any(
            p.protocol != current.protocol
            and _normalize(p.state) == "open"
            for p in previous_same_port
        )

        if current_state == "open" and previous_open_other_protocol:
            changes.append("protocol_changed")

        return changes

    previous_state = _normalize(previous_same_endpoint.state)

    # State-transition detection.
    if previous_state != "open" and current_state == "open":
        changes.append("new_port")

    elif previous_state == "open" and current_state == "closed":
        # Only an explicit Nmap CLOSED observation is sufficient.
        changes.append("closed_port")

    # filtered/open|filtered/etc. do not prove that the service disappeared.
    if previous_state != "open" or current_state != "open":
        return changes

    previous_service = _normalize(previous_same_endpoint.service)
    current_service = _normalize(current.service)

    previous_service_reliable = _service_is_reliable(
        previous_same_endpoint.service
    )
    current_service_reliable = _service_is_reliable(
        current.service
    )

    # Only claim a service change when BOTH scans positively identify
    # meaningful services.
    if (
        previous_service_reliable
        and current_service_reliable
        and previous_service != current_service
    ):
        changes.append("service_changed")

        # If the service itself changed, do not additionally claim that its
        # version changed. The versions belong to different service identities.
        return changes

    # Version comparison is meaningful only when the service identity remains
    # the same and both scans returned explicit versions.
    if (
        previous_service_reliable
        and current_service_reliable
        and previous_service == current_service
        and _version_is_reliable(previous_same_endpoint.version)
        and _version_is_reliable(current.version)
        and (previous_same_endpoint.version or "").strip()
        != (current.version or "").strip()
    ):
        changes.append("version_changed")

    return changes


def previously_open_now_missing(
    previous: Iterable[ComparableService],
    current: Iterable[ComparableService],
) -> list[ComparableService]:
    """
    Return no synthetic closed-port observations.

    Earlier V3 logic treated a previously open service that was absent from a
    later Nmap result as CLOSED. That creates false positives because absence
    can mean:

    - filtered traffic
    - host firewall behavior
    - probe timeout
    - service-detection failure
    - tcpwrapped behavior
    - temporary packet loss
    - different Nmap coverage

    closed_port must therefore be generated only from an explicit current
    observation whose state is exactly 'closed'.

    The function is retained for compatibility with the enumeration service,
    but deliberately returns an empty list.
    """

    # Consume/accept the iterables for API compatibility without interpreting
    # absence as proof of closure.
    _ = previous
    _ = current

    return []


def index_by_port(
    items: Iterable[ComparableService],
) -> dict[int, list[ComparableService]]:
    result: dict[int, list[ComparableService]] = defaultdict(list)

    for item in items:
        result[item.port].append(item)

    return dict(result)