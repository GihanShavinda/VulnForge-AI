# VulnForge AI 2.0 — V12 TLS Security Assessment

## Scope

V12 imports safe TLS evidence from:

- testssl.sh
- sslscan
- Nmap SSL scripts

It evaluates:

- SSLv2 / SSLv3
- TLS 1.0 / TLS 1.1
- weak ciphers
- certificate expiration
- hostname mismatch
- self-signed certificates
- certificate key-size indicators
- certificate chain issues
- certificate trust
- certificate age
- insecure renegotiation where scanner evidence supports it

V12 does not perform destructive testing.

## Finding model

V12 introduces `CryptoFinding`.

Each finding is classified as one of:

- `cryptographic_weakness`
- `certificate_management_problem`

A separate boolean field, `acceptable_lab_configuration`, records intentional isolated-lab exceptions.

This means a self-signed lab certificate is not automatically treated as critical.

## Self-signed certificate rule

Production-like context:
- finding type: certificate-management problem
- severity: Medium

Authorized isolated lab context:
- finding type: certificate-management problem
- severity: Low
- `acceptable_lab_configuration=true`

The rationale makes clear that intentional lab trust/pinning can be acceptable.

## API

### Parse scanner output

POST `/api/v1/tls-assessment/parse`

Example:

```json
{
  "scanner": "testssl.sh",
  "payload": [
    {
      "id": "SSLv3",
      "finding": "enabled"
    }
  ]
}
```

### Assess normalized evidence

POST `/api/v1/tls-assessment/assess`

Example:

```json
{
  "asset_id": null,
  "target": "192.168.37.20",
  "port": 443,
  "scanner": "testssl.sh",
  "source_name": "ubuntu-testssl.json",
  "lab_context": true,
  "evidence": [
    {
      "category": "certificate.self_signed",
      "observed_value": "true",
      "source_locator": "cert_selfsigned",
      "confidence": "confirmed",
      "raw": {}
    },
    {
      "category": "protocol.tls1_0",
      "observed_value": "enabled",
      "source_locator": "TLS1",
      "confidence": "high confidence",
      "raw": {}
    }
  ]
}
```

### History

GET `/api/v1/tls-assessment/imports`

GET `/api/v1/tls-assessment/imports/{import_id}/findings`

GET `/api/v1/tls-assessment/imports/{import_id}/evidence`

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1

alembic upgrade head
alembic current
```

Expected:

```text
0012_tls_security_assessment (head)
```

## Tests

```powershell
pytest -v tests/test_tls_rules.py
pytest -v tests/test_tls_rule_coverage.py
pytest -v tests/test_tls_scanner_parsers.py
pytest -v
```

## Run

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger:

`http://127.0.0.1:8000/docs`

Expected version:

`0.12.0`

Expected API group:

`tls-security-assessment`

## Notes

The scanner parsers intentionally preserve source evidence rather than inventing missing certificate or protocol attributes.

TLS findings remain separate from general vulnerability priority. A TLS weakness is evidence for cryptographic or certificate-management posture; it is not by itself proof of exploitation.
