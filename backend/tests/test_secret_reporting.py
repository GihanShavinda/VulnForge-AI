import json

from app.services.secret_reporting import safe_audit_event,safe_report_row
from app.services.secret_safety import evidence_hash,masked_fingerprint

RAW="DoNotLeakThisValue-123456789"

def _safe_dict():
    return {
        "secret_type":"api_key",
        "masked_fingerprint":masked_fingerprint("api_key",RAW),
        "location":"settings.env:7",
        "evidence_hash":evidence_hash(RAW),
        "severity":"High",
        "validation_status":"unvalidated",
        "first_seen":"2026-10-13T00:00:00Z",
        "last_seen":"2026-10-13T00:00:00Z",
        "raw_secret":RAW,
        "secret":RAW,
        "password":RAW,
    }

def test_report_projection_never_contains_raw_secret():
    blob=json.dumps(safe_report_row(_safe_dict()))
    assert RAW not in blob
    assert "raw_secret" not in blob
    assert '"secret"' not in blob
    assert '"password"' not in blob

def test_audit_event_never_contains_raw_secret():
    blob=json.dumps(safe_audit_event(_safe_dict()))
    assert RAW not in blob
    assert "raw_secret" not in blob
