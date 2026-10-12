from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class HTTPFingerprintResult:
    url: str
    status: int | None
    headers: dict[str, str]
    raw_evidence: str
    error: str | None


def fetch_http_headers(url: str, timeout_seconds: int = 5) -> HTTPFingerprintResult:
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "VulnForge-AI/0.4"})
    context = ssl.create_default_context()
    if url.lower().startswith("https://"):
        context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            raw = json.dumps({"url": url, "status": response.status, "headers": headers}, sort_keys=True)
            return HTTPFingerprintResult(url, response.status, headers, raw, None)
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()}
        raw = json.dumps({"url": url, "status": exc.code, "headers": headers}, sort_keys=True)
        return HTTPFingerprintResult(url, exc.code, headers, raw, None)
    except Exception as exc:
        raw = json.dumps({"url": url, "error": str(exc)}, sort_keys=True)
        return HTTPFingerprintResult(url, None, {}, raw, str(exc))
