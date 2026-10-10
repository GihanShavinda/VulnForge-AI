from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from xml.etree import ElementTree as ET


@dataclass(frozen=True)
class ParsedHost:
    ip_address: str
    hostname: str | None
    mac_address: str | None
    vendor: str | None
    reachable: bool
    state: str


def _normalize_mac(value: str | None) -> str | None:
    return value.upper() if value else None


def parse_nmap_xml(xml_text: str) -> tuple[datetime, list[ParsedHost]]:
    """Parse Nmap XML without trusting terminal text output."""
    root = ET.fromstring(xml_text)

    start_epoch = root.attrib.get("start")
    if start_epoch and start_epoch.isdigit():
        scan_timestamp = datetime.fromtimestamp(int(start_epoch), tz=timezone.utc)
    else:
        scan_timestamp = datetime.now(timezone.utc)

    hosts: list[ParsedHost] = []
    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        state = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"
        reachable = state == "up"

        ip_address: str | None = None
        mac_address: str | None = None
        vendor: str | None = None

        for address in host_node.findall("address"):
            addr_type = address.attrib.get("addrtype")
            if addr_type in {"ipv4", "ipv6"} and ip_address is None:
                ip_address = address.attrib.get("addr")
            elif addr_type == "mac":
                mac_address = _normalize_mac(address.attrib.get("addr"))
                vendor = address.attrib.get("vendor")

        if not ip_address:
            continue

        hostname: str | None = None
        hostnames = host_node.find("hostnames")
        if hostnames is not None:
            preferred = hostnames.find("hostname")
            if preferred is not None:
                hostname = preferred.attrib.get("name") or None

        hosts.append(
            ParsedHost(
                ip_address=ip_address,
                hostname=hostname,
                mac_address=mac_address,
                vendor=vendor,
                reachable=reachable,
                state=state,
            )
        )

    return scan_timestamp, hosts
