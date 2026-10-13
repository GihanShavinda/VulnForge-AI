import json
from app.schemas.secret_exposure import SecretExposureRead
from datetime import datetime,timezone
from uuid import uuid4
from app.services.secret_safety import evidence_hash,masked_fingerprint

RAW="NeverReturnThisSecret-123456"

def test_api_schema_has_no_raw_secret_field():
    model=SecretExposureRead(
        id=uuid4(),import_id=uuid4(),secret_type="token",
        masked_fingerprint=masked_fingerprint("token",RAW),
        location="config.env:1",evidence_hash=evidence_hash(RAW),
        severity="High",validation_status="unvalidated",
        first_seen=datetime.now(timezone.utc),last_seen=datetime.now(timezone.utc),
    )
    encoded=json.dumps(model.model_dump(mode="json"))
    assert RAW not in encoded
    assert "secret_value" not in encoded
    assert '"secret"' not in encoded

def test_log_report_audit_safe_projection_contains_no_raw_secret():
    safe_event={
        "event":"secret_exposure_detected",
        "secret_type":"token",
        "masked_fingerprint":masked_fingerprint("token",RAW),
        "evidence_hash":evidence_hash(RAW),
        "location":"config.env:1",
    }
    blob=json.dumps(safe_event)
    assert RAW not in blob
