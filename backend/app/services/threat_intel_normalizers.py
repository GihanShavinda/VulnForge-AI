from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.services.threat_intel_types import NormalizedIntelRecord


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dedupe_strings(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def normalize_nvd(payload: dict[str, Any]) -> list[NormalizedIntelRecord]:
    records: list[NormalizedIntelRecord] = []
    for wrapper in payload.get("vulnerabilities", []) or []:
        cve = wrapper.get("cve") or {}
        cve_id = str(cve.get("id") or "").strip()
        if not cve_id:
            continue

        cwes: list[str] = []
        for weakness in cve.get("weaknesses", []) or []:
            for desc in weakness.get("description", []) or []:
                value = str(desc.get("value") or "").strip()
                if value.startswith("CWE-"):
                    cwes.append(value)

        metrics = cve.get("metrics") or {}
        cvss31_score = None
        cvss31_vector = None
        cvss4_score = None
        cvss4_vector = None

        v31 = metrics.get("cvssMetricV31") or []
        if v31:
            data = (v31[0].get("cvssData") or {})
            cvss31_score = _float(data.get("baseScore"))
            cvss31_vector = data.get("vectorString")

        v40 = metrics.get("cvssMetricV40") or []
        if v40:
            data = (v40[0].get("cvssData") or {})
            cvss4_score = _float(data.get("baseScore"))
            cvss4_vector = data.get("vectorString")

        cpes: list[dict[str, Any]] = []
        affected_ranges: list[dict[str, Any]] = []
        for config in cve.get("configurations", []) or []:
            for node in config.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    criteria = match.get("criteria")
                    if criteria:
                        cpes.append({"cpe": criteria, "vulnerable": match.get("vulnerable")})
                    range_info = {
                        "cpe": criteria,
                        "versionStartIncluding": match.get("versionStartIncluding"),
                        "versionStartExcluding": match.get("versionStartExcluding"),
                        "versionEndIncluding": match.get("versionEndIncluding"),
                        "versionEndExcluding": match.get("versionEndExcluding"),
                    }
                    if any(v is not None for k, v in range_info.items() if k != "cpe"):
                        affected_ranges.append(range_info)

        references = []
        vendor_advisories = []
        for ref in cve.get("references", []) or []:
            item = {
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags") or [],
            }
            references.append(item)
            tags = {str(x).lower() for x in item["tags"]}
            if "vendor advisory" in tags:
                vendor_advisories.append(item)

        records.append(
            NormalizedIntelRecord(
                canonical_id=cve_id,
                cve_id=cve_id,
                cwes=_dedupe_strings(cwes),
                cvss31_score=cvss31_score,
                cvss31_vector=cvss31_vector,
                cvss4_score=cvss4_score,
                cvss4_vector=cvss4_vector,
                cpes=cpes,
                affected_ranges=affected_ranges,
                fixed_ranges=[],
                references=references,
                published_at=_dt(cve.get("published")),
                modified_at=_dt(cve.get("lastModified")),
                vendor_advisories=vendor_advisories,
                confidence="high confidence",
                source_record_modified_at=_dt(cve.get("lastModified")),
                raw=cve,
            )
        )
    return records


def normalize_osv(payload: dict[str, Any]) -> list[NormalizedIntelRecord]:
    osv_id = str(payload.get("id") or "").strip()
    if not osv_id:
        return []

    aliases = [str(x).strip() for x in payload.get("aliases", []) or [] if str(x).strip()]
    cve_id = next((x for x in aliases if x.startswith("CVE-")), None)
    canonical_id = cve_id or osv_id

    cwes = []
    db_specific = payload.get("database_specific") or {}
    for item in db_specific.get("cwe_ids", []) or []:
        text = str(item).strip()
        if text:
            cwes.append(text)

    cvss31_vector = None
    cvss4_vector = None
    for severity in payload.get("severity", []) or []:
        sev_type = str(severity.get("type") or "").upper()
        score = severity.get("score")
        score_text = str(score or "")
        if sev_type in {"CVSS_V3", "CVSS_V3.1"} and score_text.startswith("CVSS:3.1/"):
            cvss31_vector = score_text
        elif sev_type in {"CVSS_V4", "CVSS_V4.0"} and score_text.startswith("CVSS:4.0/"):
            cvss4_vector = score_text

    affected_ranges: list[dict[str, Any]] = []
    fixed_ranges: list[dict[str, Any]] = []
    cpes: list[dict[str, Any]] = []

    for affected in payload.get("affected", []) or []:
        package = affected.get("package") or {}
        eco = package.get("ecosystem")
        name = package.get("name")
        purl = package.get("purl")
        for rng in affected.get("ranges", []) or []:
            row = {
                "type": rng.get("type"),
                "repo": rng.get("repo"),
                "events": rng.get("events") or [],
                "ecosystem": eco,
                "package": name,
                "purl": purl,
            }
            affected_ranges.append(row)
            fixed_events = [x.get("fixed") for x in row["events"] if isinstance(x, dict) and x.get("fixed")]
            for fixed in fixed_events:
                fixed_ranges.append({
                    "fixed": fixed,
                    "ecosystem": eco,
                    "package": name,
                    "purl": purl,
                })

        versions = affected.get("versions") or []
        if versions:
            affected_ranges.append({
                "versions": versions,
                "ecosystem": eco,
                "package": name,
                "purl": purl,
            })

    references = [
        {"type": ref.get("type"), "url": ref.get("url")}
        for ref in payload.get("references", []) or []
    ]

    vendor_advisories = [
        ref for ref in references
        if str(ref.get("type") or "").upper() == "ADVISORY"
    ]

    return [
        NormalizedIntelRecord(
            canonical_id=canonical_id,
            cve_id=cve_id,
            osv_id=osv_id,
            cwes=_dedupe_strings(cwes),
            cvss31_score=None,
            cvss31_vector=cvss31_vector,
            cvss4_score=None,
            cvss4_vector=cvss4_vector,
            cpes=cpes,
            affected_ranges=affected_ranges,
            fixed_ranges=fixed_ranges,
            references=references,
            published_at=_dt(payload.get("published")),
            modified_at=_dt(payload.get("modified")),
            vendor_advisories=vendor_advisories,
            confidence="high confidence",
            source_record_modified_at=_dt(payload.get("modified")),
            raw=payload,
        )
    ]


def normalize_cisa_kev(payload: dict[str, Any]) -> list[NormalizedIntelRecord]:
    records: list[NormalizedIntelRecord] = []
    for item in payload.get("vulnerabilities", []) or []:
        cve_id = str(item.get("cveID") or "").strip()
        if not cve_id:
            continue

        ransomware_raw = item.get("knownRansomwareCampaignUse")
        ransomware = None
        if isinstance(ransomware_raw, str):
            if ransomware_raw.strip().lower() == "known":
                ransomware = True
            elif ransomware_raw.strip().lower() == "unknown":
                ransomware = None

        references = []
        notes = item.get("notes")
        if notes:
            references.append({"type": "note", "value": notes})

        records.append(
            NormalizedIntelRecord(
                canonical_id=cve_id,
                cve_id=cve_id,
                references=references,
                kev=True,
                known_ransomware_use=ransomware,
                required_action=item.get("requiredAction"),
                confidence="confirmed",
                source_record_modified_at=_dt(payload.get("dateReleased")),
                raw=item,
            )
        )
    return records


def normalize_epss(payload: dict[str, Any]) -> list[NormalizedIntelRecord]:
    records: list[NormalizedIntelRecord] = []
    for item in payload.get("data", []) or []:
        cve_id = str(item.get("cve") or "").strip()
        if not cve_id:
            continue
        records.append(
            NormalizedIntelRecord(
                canonical_id=cve_id,
                cve_id=cve_id,
                epss=_float(item.get("epss")),
                epss_percentile=_float(item.get("percentile")),
                confidence="confirmed",
                source_record_modified_at=_dt(item.get("date")),
                raw=item,
            )
        )
    return records
