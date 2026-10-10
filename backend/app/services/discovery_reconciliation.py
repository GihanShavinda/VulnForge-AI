from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from app.models.security_lab import Asset
from app.services.nmap_xml_parser import ParsedHost


@dataclass(frozen=True)
class ReconciliationResult:
    asset: Asset | None
    identity_basis: str
    changes: tuple[str, ...]


def _norm(value: str | None) -> str | None:
    return value.strip().lower() if value and value.strip() else None


def reconcile_host(host: ParsedHost, assets: Iterable[Asset]) -> ReconciliationResult:
    """
    Reconcile in deterministic priority order:
    manual asset identity (existing asset ID context is handled by caller), MAC,
    hostname, then IP. The strongest available stable identity wins.
    """
    asset_list = list(assets)

    matched: Asset | None = None
    basis = "new"

    if host.mac_address:
        for asset in asset_list:
            if _norm(getattr(asset, "mac_address", None)) == _norm(host.mac_address):
                matched, basis = asset, "mac"
                break

    if matched is None and host.hostname:
        candidates = [a for a in asset_list if _norm(a.hostname) == _norm(host.hostname)]
        if len(candidates) == 1:
            matched, basis = candidates[0], "hostname"

    if matched is None:
        for asset in asset_list:
            if asset.ip_address == host.ip_address:
                matched, basis = asset, "ip"
                break

    if matched is None:
        return ReconciliationResult(None, basis, ("new_asset",))

    changes: list[str] = []
    if matched.ip_address != host.ip_address:
        changes.append("ip_change")
    if host.hostname and _norm(matched.hostname) != _norm(host.hostname):
        changes.append("hostname_change")
    existing_mac = getattr(matched, "mac_address", None)
    if host.mac_address and existing_mac and _norm(existing_mac) != _norm(host.mac_address):
        changes.append("mac_change")
    if host.reachable and getattr(matched, "reachable", None) is False:
        changes.append("newly_reachable")

    return ReconciliationResult(matched, basis, tuple(changes))


def apply_observation(asset: Asset, host: ParsedHost, seen_at: datetime, scan_source: str) -> None:
    asset.ip_address = host.ip_address
    if host.hostname:
        asset.hostname = host.hostname
    if host.mac_address:
        asset.mac_address = host.mac_address
    if host.vendor:
        asset.vendor = host.vendor
    if asset.first_seen is None:
        asset.first_seen = seen_at
    asset.last_seen = seen_at
    asset.reachable = host.reachable
    asset.last_discovery_source = scan_source
