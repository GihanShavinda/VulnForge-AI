# VulnForge AI 2.0 — V7 Vulnerability Intelligence Layer

## Purpose

V7 adds a provenance-preserving vulnerability intelligence layer for:

- NVD CVE API 2.0
- OSV
- CISA Known Exploited Vulnerabilities (KEV)
- FIRST EPSS

V7 stores source observations independently. It does not manufacture missing fields and does not
silently merge conflicting source values.

## Normalised fields

Each `ThreatIntelObservation` can preserve:

- canonical vulnerability identifier
- CVE identifier
- OSV identifier
- CWE identifiers
- CVSS v3.1 score/vector when actually supplied
- CVSS v4 score/vector when actually supplied
- CPE applicability
- affected ranges
- fixed ranges when actually supplied
- references
- published date
- modified date
- KEV status
- EPSS score and percentile
- vendor advisory references when explicitly identified by the source
- known ransomware use when explicitly supplied by a trusted source
- required action when supplied
- source record modification timestamp
- raw source JSON
- SHA-256 of the raw source record
- observation confidence

Missing values remain `null` or empty. They are never invented.

## Source provenance and conflicts

V7 creates:

- `ThreatIntelSource`
- `IntelSyncRun`
- `ThreatIntelObservation`
- `IntelConflict`

The latest observation from each source is kept separate. If two sources provide different
non-null values for a conflict-tracked field, V7 creates an unresolved `IntelConflict`.

V7 does not automatically choose a winner.

## Freshness and staleness

Every source records:

- last attempt
- last successful refresh
- last error
- freshness threshold

`GET /api/v1/threat-intel/vulnerabilities/{canonical_id}` returns each latest source observation
with:

- source
- last refresh
- stale flag
- staleness seconds
- confidence

Default freshness windows:

- NVD: 24 hours
- OSV: 24 hours
- CISA KEV: 12 hours
- FIRST EPSS: 24 hours

## Official endpoints

Defaults can be overridden in `.env`:

```env
NVD_CVE_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=
OSV_VULNERABILITY_API_URL=https://api.osv.dev/v1/vulns
CISA_KEV_JSON_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
FIRST_EPSS_API_URL=https://api.first.org/data/v1/epss
THREAT_INTEL_CACHE_DIR=.cache/threat_intel
THREAT_INTEL_HTTP_TIMEOUT_SECONDS=30
```

An NVD API key is optional. If configured, VulnForge sends it using the `apiKey` header.

## Offline cache

Successful online fetches are written under:

```text
backend/.cache/threat_intel/
```

Use:

```json
{
  "source": "nvd",
  "identifiers": ["CVE-2021-44228"],
  "offline": true,
  "allow_cache_fallback": true
}
```

to operate from cached evidence only.

When `allow_cache_fallback` is true, a failed online fetch may fall back to an existing cache.
The sync run records whether cache was used.

Do not commit the cache directory to source control.

## API

### Sources

```text
GET /api/v1/threat-intel/sources
```

### Synchronise

```text
POST /api/v1/threat-intel/sync
```

Examples:

NVD:

```json
{
  "source": "nvd",
  "identifiers": ["CVE-2021-44228"],
  "offline": false,
  "allow_cache_fallback": true
}
```

OSV:

```json
{
  "source": "osv",
  "identifiers": ["GHSA-jfh8-c2jp-5v3q"],
  "offline": false,
  "allow_cache_fallback": true
}
```

CISA KEV:

```json
{
  "source": "cisa-kev",
  "identifiers": ["CVE-2021-44228"],
  "offline": false,
  "allow_cache_fallback": true
}
```

With an empty CISA identifier list, the full KEV catalog is normalised.

FIRST EPSS:

```json
{
  "source": "epss",
  "identifiers": ["CVE-2021-44228"],
  "offline": false,
  "allow_cache_fallback": true
}
```

### Vulnerability view

```text
GET /api/v1/threat-intel/vulnerabilities/CVE-2021-44228
```

### Sync history

```text
GET /api/v1/threat-intel/sync-runs
```

### Conflicts

```text
GET /api/v1/threat-intel/conflicts
GET /api/v1/threat-intel/conflicts?canonical_id=CVE-2021-44228
```

## Source semantics

### NVD

NVD is used for CVE metadata, CWE, CVSS, CPE applicability, references and vendor-advisory tags.
CVSS v3.1 and v4 are only populated when their corresponding metric blocks are present.

### OSV

OSV preserves OSV/GHSA identity, CVE aliases, package affected ranges and fixed events.
A CVSS vector is mapped to CVSS v3.1 only when it explicitly begins with `CVSS:3.1/`.
A CVSS v4 vector is mapped only when it explicitly begins with `CVSS:4.0/`.
V7 does not calculate a missing numeric score.

### CISA KEV

A KEV catalog record produces `kev=true`.
`knownRansomwareCampaignUse=Known` maps to `true`.
`Unknown` remains `null`; it is not converted to false.
`requiredAction` is preserved verbatim.

### FIRST EPSS

EPSS score and percentile are parsed as numeric values.
The EPSS date is retained as source-record freshness metadata rather than being mislabeled as the
vulnerability publication date.

## Install and migrate

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1

alembic upgrade head
alembic current
```

Expected:

```text
0007_threat_intelligence (head)
```

## Tests

```powershell
pytest -v tests/test_threat_intel_normalizers.py
pytest -v tests/test_threat_intel_conflicts.py
pytest -v tests/test_threat_intel_cache.py
pytest -v
```

## Run

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger:

```text
http://127.0.0.1:8000/docs
```
