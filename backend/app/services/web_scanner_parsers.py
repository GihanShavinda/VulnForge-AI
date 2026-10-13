from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any

from app.services.web_redaction import redact_headers, redact_structure, redact_text, redact_url


def _severity(value: Any) -> str:
    text = str(value or "Informational").strip().lower()
    if text in {"critical", "4"}:
        return "Critical"
    if text in {"high", "3"}:
        return "High"
    if text in {"medium", "2"}:
        return "Medium"
    if text in {"low", "1"}:
        return "Low"
    return "Informational"


def parse_zap(payload: str | dict | list) -> list[dict]:
    if isinstance(payload, str):
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = _parse_zap_xml(payload)
    else:
        data = payload

    rows: list[dict] = []
    if isinstance(data, dict):
        alerts = data.get("alerts")
        if alerts is None:
            alerts = []
            for site in data.get("site", []) or []:
                alerts.extend(site.get("alerts", []) or [])
    elif isinstance(data, list):
        alerts = data
    else:
        alerts = []

    for item in alerts or []:
        if not isinstance(item, dict):
            continue
        instances = item.get("instances") or [item]
        for instance in instances:
            url = redact_url(str(instance.get("uri") or instance.get("url") or item.get("url") or ""))
            if not url:
                continue
            request_headers = redact_text(instance.get("requestHeader") or item.get("requestHeader"))
            response_headers = redact_text(instance.get("responseHeader") or item.get("responseHeader"))
            rows.append({
                "scanner": "zap",
                "rule_id": str(item.get("pluginid") or item.get("alertRef") or "") or None,
                "title": str(item.get("alert") or item.get("name") or "ZAP finding"),
                "severity": _severity(item.get("risk") or item.get("riskdesc")),
                "method": str(instance.get("method") or "GET").upper(),
                "url": url,
                "parameter": instance.get("param") or item.get("param"),
                "request_metadata": {"headers": request_headers} if request_headers else {},
                "response_metadata": {"headers": response_headers} if response_headers else {},
                "evidence_text": redact_text(instance.get("evidence") or item.get("evidence") or item.get("desc")),
                "raw_redacted": redact_structure(item),
            })
    return rows


def _parse_zap_xml(text: str) -> dict:
    root = ET.fromstring(text)
    alerts: list[dict] = []
    for alertitem in root.findall(".//alertitem"):
        instances = []
        for inst in alertitem.findall("./instances/instance"):
            instances.append({
                "uri": inst.findtext("uri"),
                "method": inst.findtext("method"),
                "param": inst.findtext("param"),
                "evidence": inst.findtext("evidence"),
            })
        alerts.append({
            "pluginid": alertitem.findtext("pluginid"),
            "alert": alertitem.findtext("alert"),
            "riskdesc": alertitem.findtext("riskdesc"),
            "desc": alertitem.findtext("desc"),
            "instances": instances,
        })
    return {"alerts": alerts}


def parse_nikto(payload: str | dict | list) -> list[dict]:
    if isinstance(payload, str):
        stripped = payload.strip()
        if stripped.startswith("<"):
            return _parse_nikto_xml(stripped)
        data = json.loads(stripped)
    else:
        data = payload

    items = data if isinstance(data, list) else data.get("vulnerabilities", data.get("items", [])) if isinstance(data, dict) else []
    rows = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        url = redact_url(str(item.get("url") or item.get("uri") or item.get("host") or ""))
        if not url:
            continue
        rows.append({
            "scanner": "nikto",
            "rule_id": str(item.get("id") or item.get("OSVDB") or "") or None,
            "title": str(item.get("msg") or item.get("message") or "Nikto finding"),
            "severity": _severity(item.get("severity") or "low"),
            "method": str(item.get("method") or "GET").upper(),
            "url": url,
            "parameter": item.get("parameter"),
            "request_metadata": {},
            "response_metadata": {},
            "evidence_text": redact_text(item.get("msg") or item.get("message")),
            "raw_redacted": redact_structure(item),
        })
    return rows


def _parse_nikto_xml(text: str) -> list[dict]:
    root = ET.fromstring(text)
    rows = []
    for item in root.findall(".//item"):
        url = redact_url(str(item.findtext("uri") or ""))
        if not url:
            continue
        rows.append({
            "scanner": "nikto",
            "rule_id": item.get("id") or item.findtext("osvdbid"),
            "title": item.findtext("description") or "Nikto finding",
            "severity": "Low",
            "method": (item.findtext("method") or "GET").upper(),
            "url": url,
            "parameter": None,
            "request_metadata": {},
            "response_metadata": {},
            "evidence_text": redact_text(item.findtext("description")),
            "raw_redacted": {"id": item.get("id"), "uri": url, "description": redact_text(item.findtext("description"))},
        })
    return rows


def parse_nuclei(payload: str | dict | list) -> list[dict]:
    if isinstance(payload, str):
        stripped = payload.strip()
        if not stripped:
            return []
        if stripped.startswith("["):
            data = json.loads(stripped)
        elif stripped.startswith("{") and "\n" not in stripped:
            data = [json.loads(stripped)]
        else:
            data = [json.loads(line) for line in stripped.splitlines() if line.strip()]
    elif isinstance(payload, dict):
        data = [payload]
    else:
        data = payload

    rows = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        url = redact_url(str(item.get("matched-at") or item.get("host") or item.get("url") or ""))
        if not url:
            continue
        req = item.get("request")
        resp = item.get("response")
        rows.append({
            "scanner": "nuclei",
            "rule_id": str(item.get("template-id") or "") or None,
            "title": str(info.get("name") or item.get("template-id") or "Nuclei finding"),
            "severity": _severity(info.get("severity")),
            "method": str(item.get("type") or "GET").upper() if str(item.get("type") or "").lower() in {"get","post","put","delete","head","options","trace"} else "GET",
            "url": url,
            "parameter": None,
            "request_metadata": {"raw": redact_text(req)} if req else {},
            "response_metadata": {"raw": redact_text(resp)} if resp else {},
            "evidence_text": redact_text(item.get("matcher-name") or info.get("description")),
            "raw_redacted": redact_structure(item),
        })
    return rows


def parse_whatweb(payload: str | dict | list) -> list[dict]:
    if isinstance(payload, str):
        data = json.loads(payload)
    else:
        data = payload
    entries = data if isinstance(data, list) else [data]
    rows = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = redact_url(str(entry.get("target") or entry.get("url") or ""))
        plugins = entry.get("plugins") or {}
        for name, details in plugins.items():
            version = None
            if isinstance(details, dict):
                versions = details.get("version") or []
                if isinstance(versions, list) and versions:
                    version = versions[0]
                elif isinstance(versions, str):
                    version = versions
            title = f"Detected web technology: {name}" + (f" {version}" if version else "")
            rows.append({
                "scanner": "whatweb",
                "rule_id": f"whatweb:{name}",
                "title": title,
                "severity": "Informational",
                "method": "GET",
                "url": url,
                "parameter": None,
                "request_metadata": {},
                "response_metadata": {},
                "evidence_text": redact_text(json.dumps(redact_structure(details), ensure_ascii=False)),
                "raw_redacted": redact_structure({"plugin": name, "details": details}),
            })
    return rows


PARSERS = {
    "zap": parse_zap,
    "owasp zap": parse_zap,
    "nikto": parse_nikto,
    "nuclei": parse_nuclei,
    "whatweb": parse_whatweb,
}


def parse_scanner(scanner: str, payload: str | dict | list) -> list[dict]:
    key = scanner.strip().lower()
    parser = PARSERS.get(key)
    if parser is None:
        raise ValueError(f"Unsupported web scanner: {scanner}")
    return parser(payload)
