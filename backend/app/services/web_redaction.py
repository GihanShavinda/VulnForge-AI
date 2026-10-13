from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

SENSITIVE_KEY_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "session",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
    "refresh_token",
    "id_token",
)

REDACTED = "[REDACTED]"


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return normalized in SENSITIVE_HEADER_NAMES or any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in (headers or {}).items():
        result[str(key)] = REDACTED if _is_sensitive_key(str(key)) else value
    return result


def redact_url(url: str) -> str:
    url = re.sub(
        r"(?i)([?&](?:token|access_token|refresh_token|session|sid|password|passwd|api_key|apikey|key)=)[^&#]*",
        r"\1[REDACTED]",
        url,
    )
    return url


def redact_text(text: str | None) -> str | None:
    if text is None:
        return None
    value = text
    patterns = [
        (r"(?im)^(authorization\s*:\s*).+$", r"\1[REDACTED]"),
        (r"(?im)^(proxy-authorization\s*:\s*).+$", r"\1[REDACTED]"),
        (r"(?im)^(cookie\s*:\s*).+$", r"\1[REDACTED]"),
        (r"(?im)^(set-cookie\s*:\s*).+$", r"\1[REDACTED]"),
        (r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]"),
        (r"(?i)((?:token|password|passwd|sessionid|session_id|sid)\s*[=:]\s*)[^\s;&]+", r"\1[REDACTED]"),
    ]
    for pattern, replacement in patterns:
        value = re.sub(pattern, replacement, value)
    return value


def redact_structure(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _is_sensitive_key(str(key)):
                out[key] = REDACTED
            else:
                out[key] = redact_structure(item)
        return out
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, str):
        return redact_text(redact_url(value))
    return deepcopy(value)
