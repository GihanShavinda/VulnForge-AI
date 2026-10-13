from __future__ import annotations

import json
from typing import Any

from app.services.sbom_identity import normalize_ecosystem, purl_identity
from app.services.sbom_types import DirectVulnerabilityFinding, NormalizedComponent


SUPPORTED_FORMATS = {"cyclonedx", "spdx", "syft", "trivy", "grype", "os-package-inventory"}


def _supplier(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        return str(value.get("name") or value.get("text") or "").strip() or None
    return None


def _ecosystem_from_purl(purl: str | None) -> str | None:
    ecosystem, _ = purl_identity(purl)
    return ecosystem


def parse_cyclonedx(document: dict[str, Any]) -> tuple[list[NormalizedComponent], list[DirectVulnerabilityFinding]]:
    components: list[NormalizedComponent] = []
    ref_map: dict[str, NormalizedComponent] = {}

    for raw in document.get("components", []) or []:
        purl = raw.get("purl")
        properties = {
            str(x.get("name")): x.get("value")
            for x in raw.get("properties", []) or []
            if isinstance(x, dict) and x.get("name")
        }
        component = NormalizedComponent(
            name=str(raw.get("name") or "").strip(),
            version=(str(raw.get("version")).strip() if raw.get("version") is not None else None),
            ecosystem=_ecosystem_from_purl(purl) or normalize_ecosystem(raw.get("type")),
            purl=purl,
            cpe=raw.get("cpe"),
            supplier=_supplier(raw.get("supplier") or raw.get("manufacturer")),
            package_origin=properties.get("vulnforge:package_origin"),
            source="cyclonedx",
            vendor_status=properties.get("vulnforge:vendor_status"),
            evidence=raw,
            source_ref=raw.get("bom-ref"),
        )
        if component.name:
            components.append(component)
            if component.source_ref:
                ref_map[component.source_ref] = component

    findings: list[DirectVulnerabilityFinding] = []
    for vuln in document.get("vulnerabilities", []) or []:
        vuln_id = str(vuln.get("id") or "").strip()
        if not vuln_id:
            continue
        source_obj = vuln.get("source") or {}
        source = str(source_obj.get("name") or "cyclonedx")
        for affect in vuln.get("affects", []) or []:
            ref = affect.get("ref")
            component = ref_map.get(ref)
            ranges: list[str] = []
            statuses: list[str] = []
            for item in affect.get("versions", []) or []:
                if item.get("range"):
                    ranges.append(str(item["range"]))
                if item.get("version"):
                    ranges.append(str(item["version"]))
                if item.get("status"):
                    statuses.append(str(item["status"]).lower())
            if statuses and all(x not in {"affected", "unknown"} for x in statuses):
                continue
            findings.append(DirectVulnerabilityFinding(
                vulnerability_id=vuln_id,
                source=source,
                component_ref=ref,
                package_name=component.name if component else None,
                installed_version=component.version if component else None,
                ecosystem=component.ecosystem if component else None,
                purl=component.purl if component else None,
                cpe=component.cpe if component else None,
                affected_range="; ".join(ranges) or None,
                confidence="confirmed" if component else "high confidence",
                evidence=vuln,
            ))
    return components, findings


def parse_spdx(document: dict[str, Any]) -> tuple[list[NormalizedComponent], list[DirectVulnerabilityFinding]]:
    components: list[NormalizedComponent] = []
    for raw in document.get("packages", []) or []:
        purl = None
        cpe = None
        for ref in raw.get("externalRefs", []) or []:
            ref_type = str(ref.get("referenceType") or "").lower()
            locator = ref.get("referenceLocator")
            if "purl" in ref_type:
                purl = locator
            elif "cpe" in ref_type:
                cpe = locator
        component = NormalizedComponent(
            name=str(raw.get("name") or "").strip(),
            version=(str(raw.get("versionInfo")).strip() if raw.get("versionInfo") else None),
            ecosystem=_ecosystem_from_purl(purl),
            purl=purl,
            cpe=cpe,
            supplier=_supplier(raw.get("supplier")),
            package_origin=raw.get("originator"),
            source="spdx",
            evidence=raw,
            source_ref=raw.get("SPDXID"),
        )
        if component.name:
            components.append(component)
    return components, []


def parse_syft(document: dict[str, Any]) -> tuple[list[NormalizedComponent], list[DirectVulnerabilityFinding]]:
    components: list[NormalizedComponent] = []
    for raw in document.get("artifacts", []) or []:
        purl = raw.get("purl")
        cpes = raw.get("cpes") or []
        metadata = raw.get("metadata") or {}
        component = NormalizedComponent(
            name=str(raw.get("name") or "").strip(),
            version=(str(raw.get("version")).strip() if raw.get("version") is not None else None),
            ecosystem=_ecosystem_from_purl(purl) or normalize_ecosystem(raw.get("type")),
            purl=purl,
            cpe=cpes[0] if cpes else None,
            supplier=metadata.get("maintainer") or metadata.get("vendor"),
            package_origin=metadata.get("source") or metadata.get("origin"),
            source="syft",
            evidence=raw,
            source_ref=raw.get("id"),
        )
        if component.name:
            components.append(component)
    return components, []


def parse_trivy(document: dict[str, Any]) -> tuple[list[NormalizedComponent], list[DirectVulnerabilityFinding]]:
    components: list[NormalizedComponent] = []
    findings: list[DirectVulnerabilityFinding] = []
    seen: dict[tuple, NormalizedComponent] = {}

    for result in document.get("Results", []) or []:
        result_type = normalize_ecosystem(result.get("Type"))
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            pkg_name = str(vuln.get("PkgName") or "").strip()
            version = str(vuln.get("InstalledVersion") or "").strip() or None
            identifier = vuln.get("PkgIdentifier") or {}
            purl = identifier.get("PURL")
            eco = _ecosystem_from_purl(purl) or result_type
            key = (eco, pkg_name.lower(), version, purl)
            if key not in seen:
                seen[key] = NormalizedComponent(
                    name=pkg_name, version=version, ecosystem=eco, purl=purl,
                    package_origin=target, source="trivy",
                    evidence={"Target": target, "Type": result.get("Type"), "PkgIdentifier": identifier},
                    source_ref="|".join(str(x or "") for x in key),
                )
                components.append(seen[key])
            findings.append(DirectVulnerabilityFinding(
                vulnerability_id=str(vuln.get("VulnerabilityID") or "").strip(),
                source="trivy",
                component_ref=seen[key].source_ref,
                package_name=pkg_name,
                installed_version=version,
                ecosystem=eco,
                purl=purl,
                fixed_version=(str(vuln.get("FixedVersion")).strip() if vuln.get("FixedVersion") else None),
                confidence="confirmed",
                evidence=vuln,
            ))
    return [x for x in components if x.name], [x for x in findings if x.vulnerability_id]


def parse_grype(document: dict[str, Any]) -> tuple[list[NormalizedComponent], list[DirectVulnerabilityFinding]]:
    components: list[NormalizedComponent] = []
    findings: list[DirectVulnerabilityFinding] = []
    seen: dict[tuple, NormalizedComponent] = {}

    for match in document.get("matches", []) or []:
        artifact = match.get("artifact") or {}
        vuln = match.get("vulnerability") or {}
        purl = artifact.get("purl")
        name = str(artifact.get("name") or "").strip()
        version = str(artifact.get("version") or "").strip() or None
        eco = _ecosystem_from_purl(purl) or normalize_ecosystem(artifact.get("type"))
        key = (eco, name.lower(), version, purl)
        if key not in seen:
            seen[key] = NormalizedComponent(
                name=name, version=version, ecosystem=eco, purl=purl,
                cpe=(artifact.get("cpes") or [None])[0],
                package_origin=(artifact.get("locations") or [{}])[0].get("path") if artifact.get("locations") else None,
                source="grype", evidence=artifact,
                source_ref=str(artifact.get("id") or "|".join(str(x or "") for x in key)),
            )
            components.append(seen[key])

        fix = vuln.get("fix") or {}
        versions = fix.get("versions") or []
        findings.append(DirectVulnerabilityFinding(
            vulnerability_id=str(vuln.get("id") or "").strip(),
            source="grype",
            component_ref=seen[key].source_ref,
            package_name=name,
            installed_version=version,
            ecosystem=eco,
            purl=purl,
            cpe=seen[key].cpe,
            fixed_version=str(versions[0]) if versions else None,
            confidence="confirmed",
            evidence=match,
        ))
    return [x for x in components if x.name], [x for x in findings if x.vulnerability_id]


def parse_os_package_inventory(document, raw_text: str | None) -> tuple[list[NormalizedComponent], list[DirectVulnerabilityFinding]]:
    components: list[NormalizedComponent] = []
    rows = document.get("packages", []) if isinstance(document, dict) else (document if isinstance(document, list) else [])

    for raw in rows:
        if not isinstance(raw, dict):
            continue
        purl = raw.get("purl")
        component = NormalizedComponent(
            name=str(raw.get("name") or "").strip(),
            version=str(raw.get("version")).strip() if raw.get("version") is not None else None,
            ecosystem=_ecosystem_from_purl(purl) or normalize_ecosystem(raw.get("ecosystem")),
            purl=purl,
            cpe=raw.get("cpe"),
            supplier=raw.get("supplier"),
            package_origin=raw.get("origin") or raw.get("package_origin"),
            source="os-package-inventory",
            vendor_status=raw.get("vendor_status"),
            evidence=raw,
        )
        if component.name:
            components.append(component)

    if raw_text:
        for line in raw_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split("\t")
            if len(parts) < 2:
                parts = stripped.split(None, 2)
            if len(parts) < 2:
                continue
            components.append(NormalizedComponent(
                name=parts[0].strip(),
                version=parts[1].strip(),
                ecosystem="debian",
                package_origin=parts[2].strip() if len(parts) >= 3 else None,
                source="os-package-inventory",
                evidence={"raw_line": stripped},
            ))
    return components, []


def parse_sbom(fmt: str, document, raw_text: str | None = None):
    normalized = fmt.strip().lower()
    if normalized not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported SBOM/package format: {fmt}")
    if normalized == "os-package-inventory":
        return parse_os_package_inventory(document, raw_text)
    if not isinstance(document, dict):
        raise ValueError(f"{normalized} import requires a JSON object.")
    parsers = {
        "cyclonedx": parse_cyclonedx,
        "spdx": parse_spdx,
        "syft": parse_syft,
        "trivy": parse_trivy,
        "grype": parse_grype,
    }
    return parsers[normalized](document)


def canonical_payload(document, raw_text: str | None) -> bytes:
    if document is not None:
        return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return (raw_text or "").encode("utf-8")
