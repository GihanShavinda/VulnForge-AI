from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from app.models.security_lab import ScanScope


@dataclass(frozen=True)
class DiscoveryScopeDecision:
    allowed: bool
    normalized_target: str | None
    matched_scope: str | None
    reason: str


def validate_discovery_target(
    target: str,
    scopes: list[ScanScope],
    *,
    explicitly_authorized: bool,
) -> DiscoveryScopeDecision:
    """Require an IP/CIDR target to be fully contained by one approved scope."""
    value = target.strip()
    try:
        if "/" in value:
            requested = ipaddress.ip_network(value, strict=False)
        else:
            addr = ipaddress.ip_address(value)
            if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local:
                return DiscoveryScopeDecision(False, str(addr), None, "Special-use targets are not allowed.")
            requested = ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
    except ValueError:
        return DiscoveryScopeDecision(False, None, None, "Target must be a valid literal IP address or CIDR.")

    if requested.is_loopback or requested.is_multicast or requested.is_unspecified or requested.is_link_local:
        return DiscoveryScopeDecision(False, str(requested), None, "Special-use discovery ranges are not allowed.")

    for scope in scopes:
        if not scope.enabled:
            continue
        try:
            approved = ipaddress.ip_network(scope.cidr, strict=False)
        except ValueError:
            continue
        if requested.version != approved.version:
            continue
        if not requested.subnet_of(approved):
            continue
        if scope.require_explicit_authorization and not explicitly_authorized:
            return DiscoveryScopeDecision(
                False,
                str(requested),
                scope.name,
                "Explicit scan authorization is required for this scope.",
            )
        return DiscoveryScopeDecision(
            True,
            str(requested),
            scope.name,
            "Discovery target is fully contained by an enabled approved scope.",
        )

    return DiscoveryScopeDecision(False, str(requested), None, "Discovery target is outside all approved scan scopes.")
