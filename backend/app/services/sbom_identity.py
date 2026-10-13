from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import unquote

from app.services.sbom_types import NormalizedComponent


ECOSYSTEM_ALIASES = {
    "python": "pypi", "pip": "pypi", "pypi": "pypi",
    "node": "npm", "nodejs": "npm", "npm": "npm",
    "maven": "maven", "gradle": "maven", "nuget": "nuget",
    "golang": "golang", "go": "golang", "cargo": "cargo", "rust": "cargo",
    "deb": "debian", "debian": "debian", "ubuntu": "debian",
    "rpm": "rpm", "redhat": "rpm", "rhel": "rpm", "centos": "rpm",
    "alpine": "apk", "apk": "apk",
}


def normalize_ecosystem(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().lower()
    return ECOSYSTEM_ALIASES.get(text, text)


def normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip().lower())


def purl_identity(purl: str | None) -> tuple[str | None, str | None]:
    if not purl or not purl.lower().startswith("pkg:"):
        return None, None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None, None
    purl_type, path = body.split("/", 1)
    path = path.rsplit("@", 1)[0]
    path = unquote(path).strip("/")
    if not path:
        return normalize_ecosystem(purl_type), None
    return normalize_ecosystem(purl_type), normalize_name(path)


def cpe_identity(cpe: str | None) -> str | None:
    if not cpe:
        return None
    text = cpe.strip().lower()
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")
        if len(parts) >= 6:
            return ":".join(parts[:6])
    if text.startswith("cpe:/"):
        parts = text.split(":")
        if len(parts) >= 4:
            return ":".join(parts[:4])
    return text


def component_identity_key(component: NormalizedComponent) -> str:
    ecosystem, purl_name = purl_identity(component.purl)
    if ecosystem and purl_name:
        return f"purl:{ecosystem}:{purl_name}"
    cpe = cpe_identity(component.cpe)
    if cpe:
        return f"cpe:{cpe}"
    eco = normalize_ecosystem(component.ecosystem) or "unknown"
    return f"name:{eco}:{normalize_name(component.name)}"


def component_fingerprint(component: NormalizedComponent) -> str:
    payload = {
        "name": component.name,
        "version": component.version,
        "ecosystem": normalize_ecosystem(component.ecosystem),
        "purl": component.purl,
        "cpe": component.cpe,
        "supplier": component.supplier,
        "package_origin": component.package_origin,
        "source": component.source,
        "vendor_status": component.vendor_status,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
