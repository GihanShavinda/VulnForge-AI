# VulnForge AI 2.0 — V17 Environmental Risk Score 2.0

## Status

Experimental.

This scoring model is intentionally broader than CVSS. It is designed for laboratory
prioritisation experiments and should not be treated as an industry standard, exploit-success
probability, or replacement for CVSS.

## Factors

The default `ers-2.0-experimental` version uses:

- Technical severity
- Exploit probability
- Known exploitation
- Network exposure
- Service reachability
- Asset criticality
- Attack-path importance
- Privilege impact
- Credential exposure
- Security-control weakness
- Patch unavailability
- Threat relevance
- Evidence confidence
- Lifecycle risk

## Default weights

```text
technical_severity            0.12
exploit_probability           0.09
known_exploitation            0.10
network_exposure              0.08
service_reachability          0.08
asset_criticality             0.10
attack_path_importance        0.10
privilege_impact              0.06
credential_exposure           0.06
security_control_weakness     0.05
patch_unavailability          0.05
threat_relevance              0.04
evidence_confidence           0.03
lifecycle_risk                0.04
```

Weights are stored in `RiskScoreVersion` and are configurable through the API.
Custom versions must define every factor and sum to 1.0.

## Score versioning

The default version key is:

`ers-2.0-experimental`

Each score stores:

- score version ID
- calculation version
- exact weights used
- raw factors
- normalised factors
- every factor contribution
- every interaction contribution
- base score
- interaction adjustment
- final score
- priority tier
- experimental flag

This makes historical calculations reproducible when future score experiments use different weights.

## Normalisation

Examples:

- CVSS 6.5 -> 65/100
- EPSS 0.75 -> 75/100
- KEV true -> 100/100
- external network exposure -> 100/100
- isolated exposure -> 0/100
- strong security control -> 0/100 risk contribution
- no security control -> 100/100 risk contribution
- patch applied -> 0/100 patch-unavailability risk
- no vendor patch -> 100/100
- unsupported lifecycle -> 100/100

## Context interactions

V17 deliberately supports context interactions.

### Exposed + reachable + KEV + critical attack path

The default model adds:

`+12`

This permits a medium-CVSS issue with strong real-world context to outrank a technically
critical vulnerability that is isolated and effectively controlled.

### Isolated + non-reachable + strong compensating control

The default model applies:

`-20`

This does not declare the vulnerability safe. It reflects materially lower environmental
priority.

Every adjustment is stored as its own contribution row.

## Priority tiers

```text
P0  85-100
P1  70-84.99
P2  50-69.99
P3  30-49.99
P4  0-29.99
```

## API

### List score versions

GET `/api/v1/environmental-risk/versions`

Calling this endpoint creates the default score version if it does not already exist.

### Create an experimental version

POST `/api/v1/environmental-risk/versions`

Example:

```json
{
  "version_key": "ers-2.1-lab-experiment",
  "name": "ERS 2.1 Lab Experiment",
  "description": "Alternative weighting experiment.",
  "experimental": true,
  "active": true,
  "weights": {
    "technical_severity": 0.12,
    "exploit_probability": 0.09,
    "known_exploitation": 0.10,
    "network_exposure": 0.08,
    "service_reachability": 0.08,
    "asset_criticality": 0.10,
    "attack_path_importance": 0.10,
    "privilege_impact": 0.06,
    "credential_exposure": 0.06,
    "security_control_weakness": 0.05,
    "patch_unavailability": 0.05,
    "threat_relevance": 0.04,
    "evidence_confidence": 0.03,
    "lifecycle_risk": 0.04
  },
  "interaction_rules": {
    "exposed_kev_critical_path_bonus": 12,
    "isolated_nonreachable_strong_control_penalty": -20
  }
}
```

### Calculate score

POST `/api/v1/environmental-risk/score`

Example:

```json
{
  "asset_id": null,
  "vulnerability_id": "CVE-LAB-V17-001",
  "calculation_version": "ers-2.0-experimental",
  "factors": {
    "technical_severity_cvss": 6.0,
    "exploit_probability": 0.9,
    "known_exploitation": true,
    "network_exposure": "external",
    "service_reachability": "public",
    "asset_criticality": "critical",
    "attack_path_importance": "critical",
    "privilege_impact": "admin",
    "credential_exposure": "exposed",
    "security_control_strength": "weak",
    "patch_availability": "available",
    "threat_relevance": "active",
    "evidence_confidence": "confirmed",
    "lifecycle_risk": "legacy"
  }
}
```

The response exposes:

- raw factors
- normalised factors
- weights
- contribution per factor
- interaction contributions
- base score
- final score
- priority tier
- calculation version

### History

GET `/api/v1/environmental-risk/scores`

GET `/api/v1/environmental-risk/scores/{score_id}`

GET `/api/v1/environmental-risk/scores/{score_id}/contributions`

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1

alembic upgrade head
alembic current
```

Expected:

`0017_environmental_risk_score_2 (head)`

## Tests

```powershell
pytest -v tests/test_environmental_risk_normalizer.py
pytest -v tests/test_environmental_risk_engine.py
pytest -v tests/test_environmental_risk_versioning.py
pytest -v
```

## Run

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected API version:

`0.17.0`

Expected Swagger group:

`environmental-risk-score-2`

## Important limitation

This model is experimental and opinionated. Its weights and context interactions must be
validated against representative datasets before being used for operational prioritisation.
It is intended to make prioritisation explainable and reproducible, not to claim ground-truth risk.
