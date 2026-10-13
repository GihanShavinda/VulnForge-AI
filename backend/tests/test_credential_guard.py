from datetime import datetime, timezone
from types import SimpleNamespace
import pytest

from app.services.credential_guard import ensure_credential_usable, record_auth_failure, record_auth_success

def profile():
    return SimpleNamespace(enabled=True, encrypted_secret="ciphertext", failed_attempts=0, max_failed_attempts=3, lockout_until=None, last_used_at=None)

def test_lockout_after_max_failures():
    p=profile(); record_auth_failure(p); record_auth_failure(p); record_auth_failure(p)
    assert p.failed_attempts==3 and p.lockout_until is not None
    with pytest.raises(PermissionError): ensure_credential_usable(p, now=datetime.now(timezone.utc))

def test_success_resets_failures():
    p=profile(); p.failed_attempts=2; record_auth_success(p)
    assert p.failed_attempts==0 and p.lockout_until is None and p.last_used_at is not None
