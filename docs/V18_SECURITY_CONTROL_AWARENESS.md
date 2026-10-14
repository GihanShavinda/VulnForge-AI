# VulnForge AI 2.0 — V18 Security-Control Awareness

V18 adds explicit compensating-control awareness and residual-risk calculation.

## Supported controls

Host firewall, network segmentation, authentication requirement, EDR/AV, MFA,
reverse proxy, WAF, least privilege, service disabled, ACL, patch, TLS,
application allow-listing, and restricted admin access.

## Exposure effects

For a specific exposure the rule matrix classifies each control as:

- prevents
- reduces
- detects
- contains
- does_not_affect

The classification is contextual. For example, a WAF reduces a web-application
exposure, while TLS does not automatically affect that same exposure.

## Residual-risk model

Each applicable control is discounted by both effectiveness and evidence confidence.

`mitigation = effectiveness × confidence × effect multiplier`

Default effect multipliers:

- prevents = 1.00
- reduces = 0.70
- contains = 0.50
- detects = 0.20
- does_not_affect = 0.00

Multiple controls are combined multiplicatively rather than simply added.

V18 intentionally does **not** mark a vulnerability resolved because a compensating
control exists. Individual mitigation is capped at 90%, and a residual-risk floor
remains.

Expired, disabled, not-yet-effective, or elapsed temporary controls provide zero
mitigation.

## Stored evidence

Each assessment stores:

- inherent risk
- combined control effectiveness
- combined control confidence
- residual risk
- calculation version
- rationale

Each contributing control stores:

- control type
- control owner
- effect
- effectiveness
- confidence
- effective mitigation
- evidence
- temporary status
- expiry date
- mitigation-until date
- reason

## API

POST `/api/v1/security-controls`
GET `/api/v1/security-controls`
POST `/api/v1/security-controls/assess`
GET `/api/v1/security-controls/assessments`
GET `/api/v1/security-controls/assessments/{assessment_id}`
GET `/api/v1/security-controls/assessments/{assessment_id}/contributions`

## Example control

```json
{
  "asset_id": null,
  "name": "Lab WAF",
  "control_type": "waf",
  "owner": "Security Team",
  "effectiveness": 90,
  "confidence": 95,
  "evidence": {
    "source": "validated lab configuration",
    "policy": "blocking"
  },
  "temporary": false,
  "effective_from": null,
  "expires_at": null,
  "mitigation_until": null,
  "enabled": true
}
```

## Example residual-risk assessment

```json
{
  "asset_id": null,
  "vulnerability_id": "CVE-LAB-V18-001",
  "exposure_type": "web_application",
  "inherent_risk": 80,
  "control_ids": ["REPLACE_WITH_CONTROL_UUID"],
  "calculation_version": "control-aware-risk-1.0"
}
```

## Validation

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1
alembic upgrade head
alembic current
pytest -v tests/test_security_control_matrix.py
pytest -v tests/test_security_control_risk.py
pytest -v
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected Alembic head:

`0018_security_control_awareness`
