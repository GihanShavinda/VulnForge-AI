from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from app.models.security_lab import ScanScope


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    normalized_target: str | None
    allowed: bool
    matched_scope: str | None
    reason: str


def _reject_special_address(address: ipaddress._BaseAddress) -> str | None:
    if address.is_loopback:
        return "Loopback/localhost targets are not allowed."

    if address.is_multicast:
        return "Multicast targets are not allowed."

    if address.is_unspecified:
        return "Unspecified addresses are not allowed."

    if address.is_link_local:
        return "Link-local targets are not allowed."

    if getattr(address, "is_reserved", False):
        return "Reserved addresses are not allowed."

    return None


def _in_maintenance_window(scope: ScanScope, now: datetime | None = None) -> bool:
    if scope.maintenance_start is None or scope.maintenance_end is None:
        return True

    tz = ZoneInfo(scope.timezone_name)
    current = now.astimezone(tz) if now else datetime.now(tz)
    current_time = current.timetz().replace(tzinfo=None)

    start = scope.maintenance_start
    end = scope.maintenance_end

    if start == end:
        return True

    if start < end:
        return start <= current_time <= end

    # Overnight window, for example 22:00 -> 02:00.
    return current_time >= start or current_time <= end


def validate_target(
    target: str,
    scopes: list[ScanScope],
    *,
    explicitly_authorized: bool,
    now: datetime | None = None,
) -> ScopeDecision:
    """
    Validate a single literal IP target against approved scan scopes.

    V1 deliberately accepts literal IPv4/IPv6 addresses only.
    Hostname resolution is deferred to a later controlled resolver so that
    DNS cannot silently redirect a scan outside an approved network.
    """
    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError:
        return ScopeDecision(
            target=target,
            normalized_target=None,
            allowed=False,
            matched_scope=None,
            reason="Target must be a valid literal IPv4 or IPv6 address.",
        )

    special_reason = _reject_special_address(address)
    if special_reason:
        return ScopeDecision(
            target=target,
            normalized_target=str(address),
            allowed=False,
            matched_scope=None,
            reason=special_reason,
        )

    for scope in scopes:
        if not scope.enabled:
            continue

        try:
            network = ipaddress.ip_network(scope.cidr, strict=False)
        except ValueError:
            continue

        if address.version != network.version:
            continue

        # Never scan the subnet identifier or directed broadcast address.
        if isinstance(network, ipaddress.IPv4Network):
            if address == network.network_address:
                return ScopeDecision(
                    target=target,
                    normalized_target=str(address),
                    allowed=False,
                    matched_scope=scope.name,
                    reason="IPv4 network-address targets are not allowed.",
                )

            if address == network.broadcast_address:
                return ScopeDecision(
                    target=target,
                    normalized_target=str(address),
                    allowed=False,
                    matched_scope=scope.name,
                    reason="IPv4 broadcast targets are not allowed.",
                )

        if address not in network:
            continue

        if scope.require_explicit_authorization and not explicitly_authorized:
            return ScopeDecision(
                target=target,
                normalized_target=str(address),
                allowed=False,
                matched_scope=scope.name,
                reason="Explicit scan authorization is required for this scope.",
            )

        if not _in_maintenance_window(scope, now=now):
            return ScopeDecision(
                target=target,
                normalized_target=str(address),
                allowed=False,
                matched_scope=scope.name,
                reason="Target is in scope but outside the configured maintenance window.",
            )

        return ScopeDecision(
            target=target,
            normalized_target=str(address),
            allowed=True,
            matched_scope=scope.name,
            reason="Target is inside an enabled, authorized scan scope.",
        )

    return ScopeDecision(
        target=target,
        normalized_target=str(address),
        allowed=False,
        matched_scope=None,
        reason="Target is outside all approved scan scopes.",
    )
