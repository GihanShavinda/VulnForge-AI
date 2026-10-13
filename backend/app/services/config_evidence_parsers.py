from __future__ import annotations

import json
import re
from typing import Any


def parse_lynis_report(text: str) -> list[dict]:
    """
    Parse conservative key/value evidence from Lynis report-style output.
    Unknown lines are ignored rather than guessed.
    """
    evidence: list[dict] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        evidence.append(
            {
                "control_id": None,
                "category": f"lynis.{key.lower()}",
                "observed_value": value,
                "source_locator": f"line:{line_no}",
                "confidence": "high confidence",
                "raw": {"key": key, "value": value},
            }
        )
    return evidence


def parse_openscap_json(payload: dict[str, Any]) -> list[dict]:
    """
    Accept a normalized JSON export containing rule results.
    Expected item shape:
      {"id": "...", "result": "pass|fail|error|notapplicable", "title": "...", "evidence": "..."}
    """
    evidence: list[dict] = []
    for item in payload.get("results", []) or []:
        rule_id = str(item.get("id") or "").strip()
        result = str(item.get("result") or "").strip()
        if not rule_id or not result:
            continue
        evidence.append(
            {
                "control_id": None,
                "category": "openscap.rule",
                "observed_value": result,
                "source_locator": rule_id,
                "confidence": "high confidence",
                "raw": {
                    "id": rule_id,
                    "title": item.get("title"),
                    "result": result,
                    "evidence": item.get("evidence"),
                },
            }
        )
    return evidence


def parse_powershell_json(payload: dict[str, Any] | list[Any]) -> list[dict]:
    """
    Parse PowerShell-collected evidence.

    Supported shapes:
      {"evidence": [{"control_id": "...", "category": "...", "observed_value": "..."}]}
      or a direct list with the same object shape.
    """
    rows = payload if isinstance(payload, list) else payload.get("evidence", [])
    result: list[dict] = []
    for item in rows or []:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "").strip()
        observed = str(item.get("observed_value") or "").strip()
        if not category or not observed:
            continue
        result.append(
            {
                "control_id": item.get("control_id"),
                "category": category,
                "observed_value": observed,
                "source_locator": item.get("source_locator"),
                "confidence": str(item.get("confidence") or "confirmed"),
                "raw": item,
            }
        )
    return result


def parse_simple_control_lines(text: str) -> list[dict]:
    """
    Deterministic lab-friendly format:
      control_id<TAB>observed_value
    """
    result: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = re.split(r"\t+", stripped, maxsplit=1)
        if len(parts) != 2:
            continue
        control_id, observed = parts[0].strip(), parts[1].strip()
        if not control_id or not observed:
            continue
        result.append(
            {
                "control_id": control_id,
                "category": "custom.deterministic",
                "observed_value": observed,
                "source_locator": f"line:{line_no}",
                "confidence": "confirmed",
                "raw": {"control_id": control_id, "observed_value": observed},
            }
        )
    return result
