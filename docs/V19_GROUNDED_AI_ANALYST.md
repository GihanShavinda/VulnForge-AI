# VulnForge AI 2.0 — V19 Grounded AI Analyst

## Purpose

V19 adds a grounded analyst layer that reasons only from structured VulnForge evidence.

If a required claim is not supported by structured evidence, the analyst returns:

`insufficient evidence`

instead of inventing security facts.

## Evidence model

Supported structured evidence types:

- asset
- service
- confirmed_version
- cve
- cwe
- capec
- cvss
- kev
- epss
- reachability
- configuration_state
- security_control
- attack_path
- patch_information
- lifecycle_information
- evidence_confidence
- business_context
- attack_mapping

The following types are explicitly treated as **untrusted data only**:

- scanner_text
- http_page_content
- package_description
- cve_description
- imported_report_text

Content in those fields is never interpreted as instructions and is never promoted into
structured security claims.

## Output contract

The analysis JSON contains:

- executive_summary
- technical_summary
- exploitability
- evidence[]
- attack_path_effect
- business_impact
- recommended_actions[]
- verification_steps[]
- confidence
- unknowns[]

Every statement is emitted as:

```json
{
  "text": "statement",
  "evidence_ids": ["EVIDENCE-1"]
}
```

The grounding validator rejects any evidence identifier that was not supplied in the request.

## Deterministic fallback

V19 uses the deterministic fallback by default:

`vulnforge-deterministic-grounded-fallback`

It does not parse security facts out of untrusted narrative text.

Examples:

- CVE text inside scanner output does not become a CVE finding.
- A patch mentioned only in an imported report does not become a patch fact.
- A version mentioned only in a CVE description does not become a confirmed affected version.
- ATT&CK text embedded in a package description does not become an ATT&CK mapping.
- An attack path written inside HTTP page content does not become graph evidence.

A future model provider may be connected only if its output is validated by the same
grounding policy and the deterministic fallback remains available.

## API

POST `/api/v1/analyst/analyze`

GET `/api/v1/analyst/runs`

GET `/api/v1/analyst/runs/{run_id}`

## Example request

```json
{
  "calculation_version": "grounded-analyst-1.0",
  "evidence": [
    {
      "evidence_id": "ASSET-1",
      "evidence_type": "asset",
      "source": "VulnForge inventory",
      "confidence": "confirmed",
      "data": {
        "name": "ubuntu2404",
        "ip": "192.168.37.20"
      }
    },
    {
      "evidence_id": "CVE-1",
      "evidence_type": "cve",
      "source": "VulnForge vulnerability intelligence",
      "confidence": "confirmed",
      "data": {
        "cve_id": "CVE-LAB-V19-001"
      }
    },
    {
      "evidence_id": "REACH-1",
      "evidence_type": "reachability",
      "source": "VulnForge lab evidence",
      "confidence": "confirmed",
      "data": {
        "state": "reachable"
      }
    }
  ]
}
```

## Adversarial coverage

V19 tests:

- invented CVE
- invented patch
- invented affected version
- unsupported exploitability claim
- invented ATT&CK mapping
- invented attack path
- prompt injection contained inside scanner data
- prompt injection contained inside HTTP page content
- malicious package description
- malicious CVE description
- hidden instructions in imported report text

## Database records

`GroundedAnalystRun` stores:

- calculation version
- deterministic/model name
- whether fallback was used
- complete structured evidence snapshot
- complete output JSON
- grounding status
- timestamp

`GroundedAnalystAudit` records containment of untrusted narrative and grounding validation.

## Validation

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1

alembic upgrade head
alembic current

pytest -v tests/test_grounding_policy.py
pytest -v tests/test_grounded_analyst_fallback.py
pytest -v tests/test_grounded_analyst_prompt.py
pytest -v

uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected migration:

`0019_grounded_vulnforge_analyst (head)`

Expected API version:

`0.19.0`

Expected health milestone:

`V19`
