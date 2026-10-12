from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Iterable, Mapping

from app.models.enumeration import ServiceObservation
from app.services.fingerprint_confidence import FingerprintCandidate

VERSION_TOKEN = r"\d+(?:\.\d+){1,3}(?:[A-Za-z0-9._+-]*)?"


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = " ".join(value.strip().split())
    return value or None


def _confidence_from_accuracy(accuracy: int | None) -> str:
    if accuracy is None:
        return "unknown"
    if accuracy >= 98:
        return "high confidence"
    if accuracy >= 90:
        return "medium confidence"
    if accuracy >= 70:
        return "low confidence"
    return "unknown"


def _os_identity(text: str) -> tuple[str | None, str | None]:
    lower = text.lower()
    if "windows xp" in lower:
        return "Windows XP", None
    if "windows 7" in lower:
        return "Windows 7", None
    if "windows 10" in lower:
        return "Windows 10", None
    if "ubuntu" in lower:
        m = re.search(r"\bUbuntu\s+(" + VERSION_TOKEN + r")\b", text, flags=re.I)
        return "Ubuntu", m.group(1) if m else None
    if "linux" in lower:
        if " - " not in text and "–" not in text:
            m = re.search(r"\bLinux\s+(" + VERSION_TOKEN + r")\b", text, flags=re.I)
            return "Linux", m.group(1) if m else None
        return "Linux", None
    return None, None


def parse_nmap_os_xml(xml_text: str) -> list[FingerprintCandidate]:
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap OS XML evidence: {exc}") from exc

    results: list[FingerprintCandidate] = []
    for host in root.findall("host"):
        os_node = host.find("os")
        if os_node is None:
            continue
        for osmatch in os_node.findall("osmatch"):
            text = _clean(osmatch.attrib.get("name"))
            if not text:
                continue
            raw_accuracy = osmatch.attrib.get("accuracy")
            accuracy = int(raw_accuracy) if raw_accuracy and raw_accuracy.isdigit() else None
            confidence = _confidence_from_accuracy(accuracy)
            name, version = _os_identity(text)
            if name:
                results.append(FingerprintCandidate("operating_system", name, version, confidence, "nmap_os", text, "nmap/osmatch", ET.tostring(osmatch, encoding="unicode")))
            for osclass in osmatch.findall("osclass"):
                family = _clean(osclass.attrib.get("osfamily"))
                osgen = _clean(osclass.attrib.get("osgen"))
                vendor = _clean(osclass.attrib.get("vendor"))
                class_text = " ".join(x for x in [vendor, family, osgen] if x)
                class_name, class_version = _os_identity(class_text)
                if class_name:
                    raw = osclass.attrib.get("accuracy")
                    class_accuracy = int(raw) if raw and raw.isdigit() else accuracy
                    results.append(FingerprintCandidate("operating_system", class_name, class_version, _confidence_from_accuracy(class_accuracy), "nmap_os", class_text, "nmap/osclass", ET.tostring(osclass, encoding="unicode")))
        raw_os = ET.tostring(os_node, encoding="unicode")
        for match in re.finditer(r"\bLinux\s+(" + VERSION_TOKEN + r")\b", raw_os, flags=re.I):
            results.append(FingerprintCandidate("kernel", "Linux kernel", match.group(1), "medium confidence", "nmap_os", match.group(0), "nmap/os", raw_os))
    return results


def _service_candidate(observation: ServiceObservation, *, category: str, name: str, version: str | None, source_type: str, confidence: str) -> FingerprintCandidate:
    observed = " | ".join(x for x in [observation.service, observation.product, observation.version, observation.banner] if x)
    raw = json.dumps({"port": observation.port, "protocol": observation.protocol, "state": observation.state, "service": observation.service, "product": observation.product, "version": observation.version, "banner": observation.banner, "cpe": observation.cpe, "scan_confidence": observation.scan_confidence, "detection_source": observation.detection_source}, sort_keys=True)
    return FingerprintCandidate(category, name, version, confidence, source_type, observed or f"{observation.protocol}/{observation.port}", f"{observation.protocol}/{observation.port}", raw)


def candidates_from_service_observations(observations: Iterable[ServiceObservation]) -> list[FingerprintCandidate]:
    candidates: list[FingerprintCandidate] = []
    mappings = [
        ("web_server", "Apache", ("apache httpd", "apache:http_server")),
        ("web_server", "Nginx", ("nginx",)),
        ("web_server", "IIS", ("microsoft-iis", "microsoft iis")),
        ("remote_access", "OpenSSH", ("openssh",)),
        ("file_sharing", "Samba", ("samba",)),
        ("database", "MySQL", ("mysql",)),
        ("database", "PostgreSQL", ("postgresql",)),
        ("database", "MongoDB", ("mongodb",)),
        ("database", "Redis", ("redis",)),
        ("application_server", "Apache Tomcat", ("tomcat",)),
        ("application_server", "Apache JServ", ("apache jserv", "ajp13")),
    ]
    for item in observations:
        if item.state != "open":
            continue
        text = " ".join(x for x in [item.service, item.product, item.banner, item.cpe] if x).lower()
        version = _clean(item.version)
        confidence = "high confidence" if (item.scan_confidence or 0) >= 9 and item.product else "medium confidence" if item.product else "low confidence"
        source = "service_banner" if item.banner or item.product else "service_name"
        for category, name, needles in mappings:
            if any(n in text for n in needles):
                candidates.append(_service_candidate(item, category=category, name=name, version=version, source_type=source, confidence=confidence))
        php = re.search(r"\bphp[/\s-]?(" + VERSION_TOKEN + r")?\b", text, flags=re.I)
        if php:
            candidates.append(_service_candidate(item, category="language", name="PHP", version=php.group(1), source_type=source, confidence="medium confidence"))
        for name, needles in [("WordPress", ("wordpress",)), ("Drupal", ("drupal",)), ("Joomla", ("joomla",)), ("Laravel", ("laravel",)), ("Django", ("django",)), ("Express", ("express",)), ("ASP.NET", ("asp.net", "aspnet"))]:
            if any(n in text for n in needles):
                candidates.append(_service_candidate(item, category="framework", name=name, version=None, source_type=source, confidence="low confidence"))
    return candidates


def candidates_from_http_headers(headers: Mapping[str, str], *, source_locator: str, raw_evidence: str) -> list[FingerprintCandidate]:
    candidates: list[FingerprintCandidate] = []
    server = headers.get("server") or headers.get("Server")
    powered = headers.get("x-powered-by") or headers.get("X-Powered-By")
    if server:
        for name, pattern in [("Apache", r"\bApache(?:/(" + VERSION_TOKEN + r"))?"), ("Nginx", r"\bnginx(?:/(" + VERSION_TOKEN + r"))?"), ("IIS", r"\bMicrosoft-IIS(?:/(" + VERSION_TOKEN + r"))?")]:
            m = re.search(pattern, server, flags=re.I)
            if m:
                candidates.append(FingerprintCandidate("web_server", name, m.group(1), "medium confidence", "http_header", server, source_locator, raw_evidence))
    if powered:
        m = re.search(r"\bPHP(?:/(" + VERSION_TOKEN + r"))?", powered, flags=re.I)
        if m:
            candidates.append(FingerprintCandidate("language", "PHP", m.group(1), "medium confidence", "http_header", powered, source_locator, raw_evidence))
        for name, pattern in [("ASP.NET", r"ASP\.NET"), ("Express", r"\bExpress\b")]:
            if re.search(pattern, powered, flags=re.I):
                candidates.append(FingerprintCandidate("framework", name, None, "low confidence", "http_header", powered, source_locator, raw_evidence))
    return candidates


def candidates_from_whatweb(payload: object, *, source_locator: str, raw_evidence: str) -> list[FingerprintCandidate]:
    candidates: list[FingerprintCandidate] = []
    records = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
    mapping = {"apache": ("web_server", "Apache"), "nginx": ("web_server", "Nginx"), "microsoft-iis": ("web_server", "IIS"), "php": ("language", "PHP"), "openssh": ("remote_access", "OpenSSH"), "wordpress": ("framework", "WordPress"), "drupal": ("framework", "Drupal"), "joomla": ("framework", "Joomla"), "laravel": ("framework", "Laravel"), "django": ("framework", "Django"), "express": ("framework", "Express"), "asp.net": ("framework", "ASP.NET")}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("plugins", {}), dict):
            continue
        for plugin_name, plugin_value in record["plugins"].items():
            version = None
            if isinstance(plugin_value, dict):
                versions = plugin_value.get("version")
                if isinstance(versions, list) and len(versions) == 1:
                    version = _clean(str(versions[0]))
                elif isinstance(versions, str):
                    version = _clean(versions)
            mapped = mapping.get(str(plugin_name).lower())
            if mapped:
                category, name = mapped
                candidates.append(FingerprintCandidate(category, name, version, "medium confidence", "whatweb", f"{plugin_name}: {plugin_value}", source_locator, raw_evidence))
    return candidates
