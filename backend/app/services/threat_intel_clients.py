from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.services.threat_intel_cache import read_cache, write_cache


@dataclass(frozen=True)
class FetchResult:
    payloads: list[dict[str, Any]]
    cache_used: bool


class ThreatIntelFetchError(RuntimeError):
    pass


def _get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    with httpx.Client(
        timeout=settings.threat_intel_http_timeout_seconds,
        follow_redirects=True,
        headers={"User-Agent": "VulnForge-AI/0.7"},
    ) as client:
        response = client.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ThreatIntelFetchError(f"Expected a JSON object from {url}.")
        return data


def fetch_nvd(
    identifiers: list[str],
    *,
    offline: bool,
    allow_cache_fallback: bool,
) -> FetchResult:
    settings = get_settings()
    payloads: list[dict[str, Any]] = []
    cache_used = False
    ids = [x for x in identifiers if x.upper().startswith("CVE-")]
    if not ids:
        raise ThreatIntelFetchError("NVD sync requires at least one CVE identifier.")

    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    for cve_id in ids:
        key = cve_id.upper()
        if offline:
            cached = read_cache("nvd", key)
            if cached is None:
                raise ThreatIntelFetchError(f"No offline NVD cache exists for {key}.")
            payloads.append(cached)
            cache_used = True
            continue

        try:
            payload = _get_json(
                settings.nvd_cve_api_url,
                headers=headers,
                params={"cveId": key},
            )
            write_cache("nvd", key, payload)
            payloads.append(payload)
        except Exception as exc:
            if not allow_cache_fallback:
                raise ThreatIntelFetchError(f"NVD fetch failed for {key}: {exc}") from exc
            cached = read_cache("nvd", key)
            if cached is None:
                raise ThreatIntelFetchError(f"NVD fetch failed and no cache exists for {key}: {exc}") from exc
            payloads.append(cached)
            cache_used = True

    return FetchResult(payloads=payloads, cache_used=cache_used)


def fetch_osv(
    identifiers: list[str],
    *,
    offline: bool,
    allow_cache_fallback: bool,
) -> FetchResult:
    settings = get_settings()
    if not identifiers:
        raise ThreatIntelFetchError("OSV sync requires at least one OSV/CVE/GHSA identifier.")

    payloads: list[dict[str, Any]] = []
    cache_used = False

    for identifier in identifiers:
        key = identifier.strip()
        if not key:
            continue

        if offline:
            cached = read_cache("osv", key)
            if cached is None:
                raise ThreatIntelFetchError(f"No offline OSV cache exists for {key}.")
            payloads.append(cached)
            cache_used = True
            continue

        url = settings.osv_vulnerability_api_url.rstrip("/") + "/" + quote(key, safe="")
        try:
            payload = _get_json(url)
            write_cache("osv", key, payload)
            payloads.append(payload)
        except Exception as exc:
            if not allow_cache_fallback:
                raise ThreatIntelFetchError(f"OSV fetch failed for {key}: {exc}") from exc
            cached = read_cache("osv", key)
            if cached is None:
                raise ThreatIntelFetchError(f"OSV fetch failed and no cache exists for {key}: {exc}") from exc
            payloads.append(cached)
            cache_used = True

    return FetchResult(payloads=payloads, cache_used=cache_used)


def fetch_cisa_kev(
    identifiers: list[str],
    *,
    offline: bool,
    allow_cache_fallback: bool,
) -> FetchResult:
    settings = get_settings()
    key = "catalog"

    if offline:
        cached = read_cache("cisa-kev", key)
        if cached is None:
            raise ThreatIntelFetchError("No offline CISA KEV cache exists.")
        payload = cached
        cache_used = True
    else:
        try:
            payload = _get_json(settings.cisa_kev_json_url)
            write_cache("cisa-kev", key, payload)
            cache_used = False
        except Exception as exc:
            if not allow_cache_fallback:
                raise ThreatIntelFetchError(f"CISA KEV fetch failed: {exc}") from exc
            cached = read_cache("cisa-kev", key)
            if cached is None:
                raise ThreatIntelFetchError(f"CISA KEV fetch failed and no cache exists: {exc}") from exc
            payload = cached
            cache_used = True

    if identifiers:
        wanted = {x.upper() for x in identifiers if x.upper().startswith("CVE-")}
        filtered = [
            item for item in payload.get("vulnerabilities", []) or []
            if str(item.get("cveID") or "").upper() in wanted
        ]
        payload = dict(payload)
        payload["vulnerabilities"] = filtered

    return FetchResult(payloads=[payload], cache_used=cache_used)


def fetch_epss(
    identifiers: list[str],
    *,
    offline: bool,
    allow_cache_fallback: bool,
) -> FetchResult:
    settings = get_settings()
    ids = [x.upper() for x in identifiers if x.upper().startswith("CVE-")]
    if not ids:
        raise ThreatIntelFetchError("EPSS sync requires at least one CVE identifier.")

    payloads: list[dict[str, Any]] = []
    cache_used = False

    # Keep requests comfortably below FIRST's documented cve query string limit.
    batches: list[list[str]] = []
    current: list[str] = []
    length = 0
    for cve in ids:
        extra = len(cve) + (1 if current else 0)
        if current and length + extra > 1800:
            batches.append(current)
            current = []
            length = 0
        current.append(cve)
        length += extra
    if current:
        batches.append(current)

    for batch in batches:
        key = "__".join(batch)
        if offline:
            cached = read_cache("epss", key)
            if cached is None:
                raise ThreatIntelFetchError(f"No offline EPSS cache exists for batch beginning {batch[0]}.")
            payloads.append(cached)
            cache_used = True
            continue

        try:
            payload = _get_json(
                settings.first_epss_api_url,
                params={"cve": ",".join(batch)},
            )
            write_cache("epss", key, payload)
            payloads.append(payload)
        except Exception as exc:
            if not allow_cache_fallback:
                raise ThreatIntelFetchError(f"EPSS fetch failed: {exc}") from exc
            cached = read_cache("epss", key)
            if cached is None:
                raise ThreatIntelFetchError(f"EPSS fetch failed and no cache exists: {exc}") from exc
            payloads.append(cached)
            cache_used = True

    return FetchResult(payloads=payloads, cache_used=cache_used)
