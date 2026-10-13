from app.services.secret_safety import evidence_hash,masked_fingerprint,sanitize_text,is_allowlisted

RAW="super-secret-value-123456789"

def test_hash_and_mask_do_not_contain_raw_secret():
    assert RAW not in evidence_hash(RAW)
    assert RAW not in masked_fingerprint("token",RAW)

def test_sanitize_text_removes_raw_secret():
    text=f"JWT_SECRET={RAW}\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz"
    safe=sanitize_text(text)
    assert RAW not in safe
    assert "abcdefghijklmnopqrstuvwxyz" not in safe

def test_test_secret_allowlist():
    assert is_allowlisted("test-secret-example-value") is True
