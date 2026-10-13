from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        path = re.sub(r"/+", "/", parts.path or "/")
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path.rstrip("/") or "/", "", ""))
    except Exception:
        return url.strip().lower()


def normalized_family(title: str, finding_type: str | None = None) -> str:
    text = f"{finding_type or ''} {title}".lower()
    families = [
        ("security-header", ["security header", "x-frame-options", "x-content-type-options", "strict-transport-security"]),
        ("content-security-policy", ["content security policy", "content-security-policy", "csp"]),
        ("clickjacking", ["clickjacking", "x-frame-options"]),
        ("cors", ["cors", "access-control-allow-origin"]),
        ("server-banner", ["server banner", "server header", "x-powered-by"]),
        ("directory-exposure", ["directory listing", "directory indexing", "directory exposure"]),
        ("default-page", ["default page", "welcome page"]),
        ("dangerous-method", ["http methods", "dangerous method", "trace method", "put method"]),
        ("cookie-security", ["cookie", "httponly", "secure flag", "samesite"]),
        ("tls", ["tls", "ssl", "cipher"]),
        ("known-component", ["known vulnerable", "vulnerable component", "outdated"]),
        ("information-disclosure", ["information disclosure", "information leak"]),
        ("input-validation", ["injection", "xss", "sql injection", "input validation"]),
        ("authentication", ["authentication", "auth bypass", "login"]),
    ]
    for family, needles in families:
        if any(n in text for n in needles):
            return family
    cleaned = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return cleaned[:120] or "generic"


def build_dedupe_key(*, url: str, method: str | None, title: str, finding_type: str | None, parameter: str | None) -> str:
    canonical = "|".join(
        [
            normalize_url(url),
            (method or "GET").upper(),
            normalized_family(title, finding_type),
            (parameter or "").strip().lower(),
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
