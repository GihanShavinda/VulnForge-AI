from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.security_lab import CredentialProfile


LOCKOUT_MINUTES = 15


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def lockout_active(profile: CredentialProfile, now: datetime | None = None) -> bool:
    current = now or utcnow()
    return profile.lockout_until is not None and profile.lockout_until > current


def ensure_credential_usable(profile: CredentialProfile, now: datetime | None = None) -> None:
    if not profile.enabled:
        raise PermissionError("Credential profile is disabled.")
    if lockout_active(profile, now=now):
        raise PermissionError(
            f"Credential profile is temporarily locked until {profile.lockout_until.isoformat()}."
        )
    if not profile.encrypted_secret:
        raise ValueError("Credential profile has no encrypted secret. Rotate/set the V5 secret first.")


def record_auth_failure(profile: CredentialProfile, now: datetime | None = None) -> None:
    current = now or utcnow()
    profile.failed_attempts = int(profile.failed_attempts or 0) + 1
    if profile.failed_attempts >= int(profile.max_failed_attempts or 3):
        profile.lockout_until = current + timedelta(minutes=LOCKOUT_MINUTES)


def record_auth_success(profile: CredentialProfile, now: datetime | None = None) -> None:
    current = now or utcnow()
    profile.failed_attempts = 0
    profile.lockout_until = None
    profile.last_used_at = current
