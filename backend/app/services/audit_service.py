import json
from typing import Any

from sqlalchemy.orm import Session

from app.models.security_lab import AuditLog


def write_audit_log(
    db: Session,
    *,
    event_type: str,
    actor: str = "system",
    target: str | None = None,
    allowed: bool | None = None,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    record = AuditLog(
        event_type=event_type,
        actor=actor,
        target=target,
        allowed=allowed,
        reason=reason,
        details_json=json.dumps(details, sort_keys=True) if details else None,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
