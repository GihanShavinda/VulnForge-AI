# VulnForge AI 2.0 — V11 Web Application Assessment

## Purpose

V11 imports safe evidence from web application assessment tools and normalizes it into VulnForge findings.

Supported sources:
- OWASP ZAP
- Nikto
- Nuclei
- WhatWeb

V11 does not run destructive tests. It imports scanner output that has already been produced in an authorized environment.

## Assessed concepts

The V11 classifier can recognize evidence for:
- security headers
- TLS configuration
- directory exposure
- outdated web technology
- cookie security attributes
- authentication weaknesses from evidence
- input-validation findings reported by scanners
- information disclosure
- dangerous HTTP methods
- default pages
- known vulnerable components
- CORS misconfiguration indicators
- content security policy
- clickjacking protection
- server-banner disclosure

## OWASP Top 10 mapping

Mappings are asserted only where the imported evidence supports them.

Examples:
- input validation / injection evidence → A03:2021 Injection
- known vulnerable components → A06:2021 Vulnerable and Outdated Components
- authentication weakness → A07:2021 Identification and Authentication Failures
- directory/default-page/header/banner weaknesses → A05:2021 Security Misconfiguration
- weak TLS → A02:2021 Cryptographic Failures
- supported CORS weakness → A01:2021 Broken Access Control

Unsupported findings keep an empty OWASP mapping rather than inventing one.

## Evidence redaction

Before persistence, V11 redacts:
- cookies
- Set-Cookie values
- Authorization / Proxy-Authorization
- bearer tokens
- session identifiers
- password/credential fields
- API keys / token-like query-string parameters

The database stores only redacted imported metadata.

## Evidence deduplication

V11 deduplicates evidence across ZAP, Nikto, and Nuclei using a SHA-256 fingerprint derived from:
- normalized URL without query string
- HTTP method
- normalized finding family
- affected parameter

This allows semantically equivalent findings such as "Directory Listing" and "Directory indexing enabled" at the same endpoint to collapse to one evidence record.

## Models

- WebAssessmentImport
- WebEvidence
- WebFinding

## API

### Import scanner evidence

POST `/api/v1/web-assessment/imports`

Example ZAP payload:

```json
{
  "asset_id": null,
  "target_url": "https://example.test",
  "scanner": "zap",
  "source_name": "zap-report.json",
  "payload": {
    "alerts": [
      {
        "pluginid": "10020",
        "alert": "Missing Security Header",
        "risk": "Medium",
        "instances": [
          {
            "uri": "https://example.test/",
            "method": "GET",
            "requestHeader": "Authorization: Bearer secret",
            "responseHeader": "Server: nginx",
            "evidence": "X-Content-Type-Options missing"
          }
        ]
      }
    ]
  }
}
```

### Import Nuclei JSONL

The `payload` field may be a JSONL string.

### Import Nikto

The `payload` field may be Nikto XML or JSON.

### Import WhatWeb

The `payload` field may be WhatWeb JSON.

### List imports

GET `/api/v1/web-assessment/imports`

### Findings

GET `/api/v1/web-assessment/imports/{import_id}/findings`

### Evidence

GET `/api/v1/web-assessment/imports/{import_id}/evidence`

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1

alembic upgrade head
alembic current
```

Expected:

```text
0011_web_application_assessment (head)
```

## Tests

```powershell
pytest -v tests/test_web_redaction.py
pytest -v tests/test_web_deduplication.py
pytest -v tests/test_web_scanner_parsers.py
pytest -v tests/test_web_owasp_mapping.py
pytest -v
```

## Run

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger:
`http://127.0.0.1:8000/docs`

Expected application version:
`0.11.0`

Expected API group:
`web-application-assessment`

## Safety boundary

V11 is evidence-import and analysis functionality only.

It does not:
- launch ZAP active scans
- launch Nikto
- launch Nuclei
- fuzz endpoints
- perform destructive requests
- attempt exploitation
- bypass authentication

Use source tools only against systems you are authorized to assess.
