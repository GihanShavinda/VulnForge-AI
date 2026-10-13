from __future__ import annotations

import re


# ============================================================
# Deterministic secret patterns
# ============================================================
#
# IMPORTANT:
#
# These patterns return candidate secrets only to the internal
# assessment pipeline.
#
# The raw candidate must never be persisted or returned through
# API/report/audit/log output.
#
# The service layer converts candidates into HMAC fingerprints
# before storing findings.
# ============================================================


PATTERNS = [
    # --------------------------------------------------------
    # OpenSSH private key
    # --------------------------------------------------------
    (
        "ssh_private_key",
        re.compile(
            r"-----BEGIN OPENSSH PRIVATE KEY-----"
            r"[\s\S]+?"
            r"-----END OPENSSH PRIVATE KEY-----"
        ),
        "Critical",
    ),

    # --------------------------------------------------------
    # PEM private keys
    #
    # Covers examples such as:
    #
    # -----BEGIN PRIVATE KEY-----
    # -----BEGIN RSA PRIVATE KEY-----
    # -----BEGIN EC PRIVATE KEY-----
    # -----BEGIN DSA PRIVATE KEY-----
    # --------------------------------------------------------
    (
        "private_key",
        re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |DSA )?"
            r"PRIVATE KEY-----"
            r"[\s\S]+?"
            r"-----END "
            r"(?:RSA |EC |DSA )?"
            r"PRIVATE KEY-----"
        ),
        "Critical",
    ),

    # --------------------------------------------------------
    # Database / service connection strings
    # --------------------------------------------------------
    (
        "database_connection_string",
        re.compile(
            r"(?i)"
            r"(?:"
            r"postgres(?:ql)?|"
            r"mysql|"
            r"mongodb(?:\+srv)?|"
            r"redis"
            r")"
            r"://"
            r"[^\s\"']+"
        ),
        "High",
    ),

    # --------------------------------------------------------
    # JWT signing secret
    # --------------------------------------------------------
    (
        "jwt_secret",
        re.compile(
            r"(?im)"
            r"^\s*"
            r"(?:"
            r"JWT_SECRET|"
            r"JWT_SIGNING_KEY"
            r")"
            r"\s*=\s*"
            r"[\"']?"
            r"([^\s\"']{8,})"
        ),
        "High",
    ),

    # --------------------------------------------------------
    # AWS access-key identifier pattern
    #
    # This identifies exposure indicators.
    # VulnForge does not validate the credential against AWS.
    # --------------------------------------------------------
    (
        "cloud_credential_pattern",
        re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
        "Critical",
    ),

    # --------------------------------------------------------
    # Generic API keys
    # --------------------------------------------------------
    (
        "api_key",
        re.compile(
            r"(?im)"
            r"^\s*"
            r"(?:"
            r"API_KEY|"
            r"APIKEY|"
            r"X_API_KEY"
            r")"
            r"\s*=\s*"
            r"[\"']?"
            r"([^\s\"']{12,})"
        ),
        "High",
    ),

    # --------------------------------------------------------
    # Tokens
    # --------------------------------------------------------
    (
        "token",
        re.compile(
            r"(?im)"
            r"^\s*"
            r"(?:"
            r"TOKEN|"
            r"ACCESS_TOKEN|"
            r"REFRESH_TOKEN"
            r")"
            r"\s*=\s*"
            r"[\"']?"
            r"([^\s\"']{12,})"
        ),
        "High",
    ),

    # --------------------------------------------------------
    # Password assignments
    # --------------------------------------------------------
    (
        "password_assignment",
        re.compile(
            r"(?im)"
            r"^\s*"
            r"(?:"
            r"PASSWORD|"
            r"PASSWD|"
            r"DB_PASSWORD"
            r")"
            r"\s*=\s*"
            r"[\"']?"
            r"([^\s\"']{6,})"
        ),
        "High",
    ),
]


def _clean_secret(
    value: str,
) -> str:
    """
    Remove surrounding syntax that may have been captured from a
    configuration file.

    The function does not transform the actual secret before hashing
    except for surrounding quotes / common line delimiters.
    """

    return (
        value
        .strip()
        .strip('"')
        .strip("'")
        .rstrip(",;")
    )


def scan_text(
    text: str,
    location: str,
) -> list[dict]:
    """
    Scan text with deterministic patterns.

    Raw candidates exist only transiently in this return structure.
    They must immediately be passed to the SecretExposure service,
    which converts them to safe HMAC fingerprints.

    Do not log the returned dictionaries.
    """

    results: list[dict] = []

    for (
        secret_type,
        regex,
        severity,
    ) in PATTERNS:

        for match in regex.finditer(text):

            # A pattern with a capturing group returns only the
            # credential value. Whole-key patterns such as PEM keys
            # use the entire match.
            if match.lastindex:
                raw_secret = match.group(
                    match.lastindex
                )
            else:
                raw_secret = match.group(0)

            secret = _clean_secret(
                raw_secret
            )

            if not secret:
                continue

            line_number = (
                text[
                    : match.start()
                ].count("\n")
                + 1
            )

            results.append(
                {
                    "secret_type": secret_type,
                    "secret": secret,
                    "severity": severity,
                    "location": (
                        f"{location}:"
                        f"{line_number}"
                    ),
                    "validation_status": (
                        "unvalidated"
                    ),
                }
            )

    return results