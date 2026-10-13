# VulnForge AI 2.0 — V8 Weakness & Adversary-Technique Context

## Purpose

V8 adds a conservative context layer that links vulnerability intelligence to security weaknesses,
attack patterns, and possible ATT&CK behaviour.

The core chain is:

```text
CVE / vulnerability intelligence
        ↓
CWE
        ↓
CAPEC
        ↓
possible ATT&CK technique context
```

The chain is contextual. It is not evidence that an adversary actually performed an ATT&CK
technique.

## Behaviour states

V8 deliberately separates:

- `potential` — a technique may be relevant based on weakness/finding context
- `observed` — telemetry or evidence indicates technique-like behaviour was seen
- `confirmed` — correlated evidence justifies a confirmed behavioural classification

A vulnerability or CWE alone can produce only `potential` mappings.

`observed` and `confirmed` records require non-empty evidence.

## Models

V8 adds:

- `AttackTechnique`
- `WeaknessCapecMapping`
- `WeaknessTechniqueMapping`
- `BehaviourObservation`

Each mapping stores:

- tactic
- technique
- sub-technique where applicable
- mapping confidence
- mapping source
- mapping rationale

## Curated CWE → CAPEC mappings

The initial conservative catalog includes:

- CWE-79 → CAPEC-63 Cross-Site Scripting
- CWE-89 → CAPEC-66 SQL Injection
- CWE-78 → CAPEC-88 OS Command Injection
- CWE-22 → CAPEC-126 Path Traversal

Unsupported CWE values return no CAPEC mapping rather than a guessed one.

## ATT&CK catalog

The bundled catalog includes techniques relevant to the requested contexts, including:

- Initial Access — T1190 Exploit Public-Facing Application
- Execution — T1059 Command and Scripting Interpreter
- Execution — T1059.001 PowerShell
- Execution — T1059.003 Windows Command Shell
- Execution — T1059.004 Unix Shell
- Privilege Escalation — T1068 Exploitation for Privilege Escalation
- Credential Access — T1003 OS Credential Dumping
- Discovery — T1087 Account Discovery / T1087.001 Local Account
- Lateral Movement — T1210 Exploitation of Remote Services
- Collection — T1005 Data from Local System
- Command and Control — T1071.001 Web Protocols
- Exfiltration — T1041 Exfiltration Over C2 Channel

The catalog does not imply those techniques occurred.

## API

### CVE / vulnerability context

```text
GET /api/v1/weakness-context/vulnerabilities/{canonical_id}
```

Example:

```text
GET /api/v1/weakness-context/vulnerabilities/CVE-2021-44228
```

Response separates:

```json
{
  "canonical_id": "CVE-2021-44228",
  "security_weaknesses": [],
  "possible_attacker_behaviour": [],
  "observed_or_confirmed_behaviour": [],
  "disclaimer": "..."
}
```

`security_weaknesses` are derived from V7 threat-intelligence observations.

### Add a potential finding → ATT&CK mapping

```text
POST /api/v1/weakness-context/finding-technique-mappings
```

Example:

```json
{
  "finding_id": "finding-web-001",
  "attack_id": "T1190",
  "mapping_confidence": "medium confidence",
  "mapping_source": "analyst-context",
  "mapping_rationale": "The finding affects an externally reachable application and could support exploitation for initial access."
}
```

This creates a `potential` mapping only.

### Record observed behaviour

```text
POST /api/v1/weakness-context/behaviour-observations
```

Example:

```json
{
  "finding_id": "finding-web-001",
  "canonical_id": "CVE-2021-44228",
  "attack_id": "T1190",
  "context_type": "observed",
  "mapping_confidence": "high confidence",
  "mapping_source": "lab telemetry correlation",
  "mapping_rationale": "A crafted exploit request was observed against the vulnerable service.",
  "evidence": {
    "request_event_id": "evt-123"
  }
}
```

### Record confirmed behaviour

Use `context_type = confirmed` only when evidence supports it:

```json
{
  "finding_id": "finding-web-001",
  "canonical_id": "CVE-2021-44228",
  "attack_id": "T1190",
  "context_type": "confirmed",
  "mapping_confidence": "confirmed",
  "mapping_source": "correlated lab evidence",
  "mapping_rationale": "The exploit request was correlated with post-exploitation process creation on the same host.",
  "evidence": {
    "request_event_id": "evt-123",
    "process_event_id": "evt-456"
  }
}
```

### Finding context

```text
GET /api/v1/weakness-context/findings/{finding_id}
```

### Behaviour observations

```text
GET /api/v1/weakness-context/behaviour-observations
```

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1

alembic upgrade head
alembic current
```

Expected:

```text
0008_weakness_adversary_context (head)
```

## Tests

```powershell
pytest -v tests/test_weakness_attack_catalog.py
pytest -v tests/test_behaviour_observation_schema.py
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

Expected API group:

```text
weakness-adversary-context
```
