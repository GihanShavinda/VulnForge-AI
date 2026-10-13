from __future__ import annotations

import hashlib
import hmac
import re

from app.core.config import get_settings


MASK = "[REDACTED]"


def _key() -> bytes:
    """
    Return the dedicated key used to create safe HMAC fingerprints.

    Raw credentials are never persisted. The HMAC allows VulnForge
    to determine whether the same credential was observed elsewhere
    without retaining the credential itself.
    """

    settings = get_settings()

    value = getattr(
        settings,
        "secret_fingerprint_key",
        "",
    )

    # Development fallback only.
    #
    # Production/lab deployments should configure:
    #
    # VULNFORGE_SECRET_FINGERPRINT_KEY=<random-value>
    #
    # Do not reuse VULNFORGE_CREDENTIAL_KEY.
    return (
        value
        or "vulnforge-development-secret-fingerprint-key"
    ).encode("utf-8")


def evidence_hash(secret: str) -> str:
    """
    Produce a stable HMAC-SHA256 fingerprint of a secret.

    The original secret cannot be recovered from the stored value.
    """

    return hmac.new(
        _key(),
        secret.encode(
            "utf-8",
            "ignore",
        ),
        hashlib.sha256,
    ).hexdigest()


def masked_fingerprint(
    secret_type: str,
    secret: str,
) -> str:
    """
    Return a short safe identifier suitable for UI/API output.

    Example:

        api_key:5d99828e8204

    The actual credential is never included.
    """

    digest = evidence_hash(secret)

    return f"{secret_type}:{digest[:12]}"


def sanitize_location(
    location: str,
) -> str:
    """
    Remove accidental credential-like values from locations.

    Example:

        config.env?token=secret-value

    becomes:

        config.env?token=[REDACTED]
    """

    return re.sub(
        r"(?i)(token|secret|password|passwd|key)=([^\s&]+)",
        r"\1=[REDACTED]",
        location,
    )


def sanitize_text(
    text: str,
) -> str:
    """
    Redact credential material before text can be written to
    logs, reports, diagnostics, or audit output.

    This function is intentionally conservative.
    """

    output = text

    # ---------------------------------------------------------
    # Authorization headers
    # ---------------------------------------------------------

    output = re.sub(
        r"(?im)^(authorization\s*:\s*)([^\r\n]+)$",
        r"\1[REDACTED]",
        output,
    )

    output = re.sub(
        r"(?im)^(proxy-authorization\s*:\s*)([^\r\n]+)$",
        r"\1[REDACTED]",
        output,
    )

    # ---------------------------------------------------------
    # Cookie headers
    # ---------------------------------------------------------

    output = re.sub(
        r"(?im)^(cookie\s*:\s*)([^\r\n]+)$",
        r"\1[REDACTED]",
        output,
    )

    output = re.sub(
        r"(?im)^(set-cookie\s*:\s*)([^\r\n]+)$",
        r"\1[REDACTED]",
        output,
    )

    # ---------------------------------------------------------
    # Common assignments
    #
    # Handles examples such as:
    #
    # JWT_SECRET=value
    # PASSWORD=value
    # token=value
    # api_key=value
    # ---------------------------------------------------------

    output = re.sub(
        (
            r"(?i)"
            r"("
            r"(?:"
            r"token|"
            r"access[_-]?token|"
            r"refresh[_-]?token|"
            r"secret|"
            r"jwt[_-]?secret|"
            r"password|"
            r"passwd|"
            r"api[_-]?key"
            r")"
            r"\s*[=:]\s*"
            r"[\"']?"
            r")"
            r"([^\s\"';&]+)"
        ),
        r"\1[REDACTED]",
        output,
    )

    # ---------------------------------------------------------
    # Bearer tokens
    # ---------------------------------------------------------

    output = re.sub(
        r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+",
        r"\1[REDACTED]",
        output,
    )

    # ---------------------------------------------------------
    # PEM/OpenSSH private keys
    # ---------------------------------------------------------

    output = re.sub(
        (
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END [A-Z ]*PRIVATE KEY-----"
        ),
        MASK,
        output,
    )

    return output


def is_allowlisted(
    secret: str,
    allowlisted_hashes: list[str] | None = None,
) -> bool:
    """
    Determine whether a detected candidate should be suppressed.

    Built-in values cover obvious development/test placeholders.

    Additional allow-list entries must be supplied as already
    generated evidence hashes rather than raw secret values.
    """

    normalized = secret.strip().lower()

    placeholder_markers = (
        "example",
        "changeme",
        "change_me",
        "change-me",
        "dummy",
        "placeholder",
        "test-secret",
        "test_secret",
        "test-secret-value",
        "not-a-real-secret",
        "not_a_real_secret",
        "replace-me",
        "replace_me",
    )

    if any(
        marker in normalized
        for marker in placeholder_markers
    ):
        return True

    supplied_hashes = {
        value.strip().lower()
        for value in (
            allowlisted_hashes
            or []
        )
        if value.strip()
    }

    return (
        evidence_hash(secret).lower()
        in supplied_hashes
    )