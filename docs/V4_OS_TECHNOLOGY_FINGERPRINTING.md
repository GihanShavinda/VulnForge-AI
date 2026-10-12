# VulnForge AI 2.0 — V4 OS & Technology Fingerprinting

V4 adds evidence-backed operating-system and technology fingerprinting.

## Evidence sources

- Nmap OS detection
- Existing V3 service observations and banners
- HTTP response headers
- Optional WhatWeb JSON output
- Explicit authenticated inventory supplied as trusted evidence

Every conclusion is represented by `TechnologyObservation` and is traceable to `FingerprintEvidence`.

## Confidence levels

- confirmed
- high confidence
- medium confidence
- low confidence
- unknown

The observed value and confidence are stored separately.

## Exact-version rule

V4 stores an exact version only when an evidence source explicitly supplies it. If equally strong evidence disagrees on a version, the aggregate version is left null and the observation is marked `conflicting`.

## Conflicting evidence

V4 preserves conflicting evidence instead of overwriting it. A preferred observation is chosen by evidence confidence/source priority, while `conflict_state` remains visible.

## Legacy OS handling

Legacy/unsupported lifecycle flags are separate from CVEs. V4 does not create CVE findings from lifecycle status.

Windows XP and Windows 7 are marked legacy. Windows 10 and Ubuntu lifecycle status is not guessed without sufficient edition/release context. Older Ubuntu release evidence is flagged for standard-support review without inferring ESM/subscription state.

## API

Run fingerprinting:

```http
POST /api/v1/fingerprints
```

Example:

```json
{
  "asset_id": "3998a69d-d323-4949-b83d-9dc7ea19a7f4",
  "explicitly_authorized": true,
  "run_nmap_os": true,
  "run_whatweb": true,
  "collect_http_headers": true,
  "authenticated_inventory": []
}
```

List asset observations:

```http
GET /api/v1/assets/{asset_id}/technologies
```

Get evidence:

```http
GET /api/v1/fingerprints/{job_id}/evidence
```

Technology catalog:

```http
GET /api/v1/technologies
```

## WhatWeb

WhatWeb is optional. If missing, the job completes with warnings and still uses other evidence sources. Set `WHATWEB_PATH` if installed outside PATH.

## Nmap OS detection

Nmap `-O` may require elevated privileges/Npcap capabilities on Windows. V4 treats Nmap OS failure as a warning rather than fabricating an OS result.

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1
alembic upgrade head
alembic current
```

Expected:

```text
0004_fingerprinting (head)
```

## Tests

```powershell
pytest -v tests/test_fingerprint_confidence.py
pytest -v tests/test_fingerprint_parser.py
pytest -v tests/test_nmap_os_runner.py
pytest -v
```
