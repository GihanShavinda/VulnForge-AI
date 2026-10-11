from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class ParsedService:
    ip_address: str
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None
    banner: str | None
    cpe: str | None
    tls_indicator: bool
    scan_confidence: int | None
    detection_source: str
    script_outputs: dict[str, str]


def _scan_timestamp(root: ET.Element) -> datetime:
    raw = root.attrib.get("start")
    if raw and raw.isdigit():
        return datetime.fromtimestamp(int(raw), tz=timezone.utc)
    return datetime.now(timezone.utc)


def _text(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def parse_nmap_service_xml(xml_text: str) -> tuple[datetime, list[ParsedService]]:
    if not xml_text.strip():
        raise ValueError("Nmap XML evidence is empty.")

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML evidence: {exc}") from exc

    observations: list[ParsedService] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue

        ip_address = None
        for address in host.findall("address"):
            if address.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                ip_address = address.attrib.get("addr")
                break
        if not ip_address:
            continue

        ports = host.find("ports")
        if ports is None:
            continue

        for port_el in ports.findall("port"):
            protocol = port_el.attrib.get("protocol", "unknown")
            try:
                port = int(port_el.attrib["portid"])
            except (KeyError, ValueError):
                continue

            state_el = port_el.find("state")
            state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"

            service_el = port_el.find("service")
            service_name = product = version = extrainfo = None
            cpes: list[str] = []
            tls_indicator = False
            confidence = None
            detection_source = "nmap-port-state"

            if service_el is not None:
                service_name = _text(service_el.attrib.get("name"))
                product = _text(service_el.attrib.get("product"))
                version = _text(service_el.attrib.get("version"))
                extrainfo = _text(service_el.attrib.get("extrainfo"))
                cpes = [c.text.strip() for c in service_el.findall("cpe") if c.text and c.text.strip()]
                tunnel = (service_el.attrib.get("tunnel") or "").lower()
                svc_lower = (service_name or "").lower()
                tls_indicator = tunnel == "ssl" or svc_lower in {"https", "ssl", "https-alt"} or "ssl" in svc_lower
                conf_raw = service_el.attrib.get("conf")
                if conf_raw and conf_raw.isdigit():
                    confidence = int(conf_raw)
                detection_source = "nmap-service-probe"

            scripts: dict[str, str] = {}
            for script in port_el.findall("script"):
                script_id = script.attrib.get("id")
                output = script.attrib.get("output")
                if script_id and output:
                    scripts[script_id] = output.strip()

            banner = scripts.get("banner") or extrainfo
            if scripts and detection_source == "nmap-port-state":
                detection_source = "nmap-nse"
            elif scripts:
                detection_source = "nmap-service-probe+nse"

            observations.append(
                ParsedService(
                    ip_address=ip_address,
                    port=port,
                    protocol=protocol,
                    state=state,
                    service=service_name,
                    product=product,
                    version=version,
                    banner=banner,
                    cpe=",".join(cpes) if cpes else None,
                    tls_indicator=tls_indicator,
                    scan_confidence=confidence,
                    detection_source=detection_source,
                    script_outputs=scripts,
                )
            )

    return _scan_timestamp(root), observations


def scripts_as_json(service: ParsedService) -> str | None:
    return json.dumps(service.script_outputs, sort_keys=True) if service.script_outputs else None
