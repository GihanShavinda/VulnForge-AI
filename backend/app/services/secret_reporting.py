from __future__ import annotations

from app.models.secret_exposure import SecretExposure


SAFE_FIELDS = (
    "secret_type",
    "masked_fingerprint",
    "location",
    "evidence_hash",
    "severity",
    "validation_status",
    "first_seen",
    "last_seen",
)


def safe_secret_projection(exposure: SecretExposure | dict) -> dict:
    """
    Produce the only representation permitted for reports, audit events and logs.
    Raw secret values are never accepted as output fields.
    """
    if isinstance(exposure, dict):
        source = exposure
        return {key: source.get(key) for key in SAFE_FIELDS if key in source}

    return {
        "secret_type": exposure.secret_type,
        "masked_fingerprint": exposure.masked_fingerprint,
        "location": exposure.location,
        "evidence_hash": exposure.evidence_hash,
        "severity": exposure.severity,
        "validation_status": exposure.validation_status,
        "first_seen": exposure.first_seen,
        "last_seen": exposure.last_seen,
    }


def safe_audit_event(exposure: SecretExposure | dict) -> dict:
    return {
        "event": "secret_exposure_detected",
        "details": safe_secret_projection(exposure),
    }


def safe_report_row(exposure: SecretExposure | dict) -> dict:
    return safe_secret_projection(exposure)
