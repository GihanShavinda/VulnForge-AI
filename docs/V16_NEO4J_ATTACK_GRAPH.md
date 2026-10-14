# VulnForge AI 2.0 — V16 Neo4j Attack Graph

## Purpose

V16 adds an evidence-aware Neo4j attack graph for the authorized VulnForge lab.

The graph models possible security relationships. It does **not** execute exploits,
attempt lateral movement, validate credentials against targets, or claim that a path
was successfully exploited.

A path is theoretical unless every edge in that path has `evidence_status=confirmed`.

## Neo4j

V16 uses a native Neo4j service.

No Docker or Docker Compose is required.

Environment variables:

```text
NEO4J_URI=bolt://127.0.0.1:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=<your-local-neo4j-password>
```

Do not paste the real password into source code.

If the Python driver is not already installed:

```powershell
pip install neo4j
```

## Node labels

V16 accepts exactly these labels:

- Network
- Asset
- Service
- Application
- Account
- Credential
- Vulnerability
- ConfigFinding
- SecretFinding
- SecurityControl
- SensitiveAsset
- UserRole
- TrustBoundary

## Relationships

V16 accepts exactly:

- CONNECTED_TO
- EXPOSES
- RUNS
- HAS_VULNERABILITY
- USES_ACCOUNT
- HAS_CREDENTIAL
- CAN_ACCESS
- TRUSTS
- REACHABLE_FROM
- PROTECTED_BY
- ENABLES
- AFFECTS
- MEMBER_OF
- AUTHENTICATES_TO

The allow-list prevents arbitrary relationship or label injection into dynamic Cypher.

## Supported starting scenarios

### Internet-style starting point

Scenario:

`internet`

Automatically creates:

`scenario:internet`

as a `TrustBoundary` node.

### Kali lab attacker

Scenario:

`kali_lab_attacker`

Automatically creates:

`scenario:kali-lab-attacker`

as an authorized lab `Asset`.

### Low-privilege internal user

Scenario:

`low_privilege_internal_user`

Automatically creates:

`scenario:low-priv-user`

as a `UserRole`.

### Compromised workstation

Scenario:

`compromised_workstation`

Automatically creates:

`scenario:compromised-workstation`

as an assumed-compromised `Asset`.

The compromised-workstation scenario is an analytical assumption. VulnForge does not
compromise a workstation to prove the path.

## Evidence status

Every edge stores:

- evidence status
- confidence
- source
- details

Allowed edge statuses:

- confirmed
- supported
- theoretical
- unknown

A path is `evidence-confirmed` only if **every edge** is confirmed.

If even one edge is supported, theoretical, or unknown, the whole path remains:

`theoretical`

This is deliberately conservative.

## Path metrics

Stored path records include:

- path length
- entry-point exposure
- weakest control
- critical destination
- number of enabling findings
- credential dependency
- privilege increase
- reachable high-value asset
- path status
- confidence
- confidence score
- complete path evidence
- node sequence
- relationship sequence
- rationale

## Example graph

A theoretical lab chain can represent:

```text
Kali lab attacker
→ exposed web server
→ vulnerable service
→ application server
→ credential
→ database
```

For example:

```text
scenario:kali-lab-attacker
  REACHABLE_FROM
asset:web

asset:web
  EXPOSES
service:http

service:http
  HAS_VULNERABILITY
vuln:lab-web

vuln:lab-web
  ENABLES
application:app01

application:app01
  HAS_CREDENTIAL
credential:db-app

credential:db-app
  AUTHENTICATES_TO
sensitive:database
```

The relationship chain itself does not imply exploitation.

## Sync API

POST `/api/v1/attack-graph/sync`

Example:

```json
{
  "scenario": "kali_lab_attacker",
  "nodes": [
    {
      "key": "asset:web",
      "label": "Asset",
      "name": "Lab Web Server",
      "properties": {
        "ip": "192.168.37.20",
        "exposure": "lab"
      }
    },
    {
      "key": "service:http",
      "label": "Service",
      "name": "HTTP Service",
      "properties": {
        "port": 80
      }
    },
    {
      "key": "vuln:lab-web",
      "label": "Vulnerability",
      "name": "Lab Vulnerability",
      "properties": {}
    },
    {
      "key": "application:app01",
      "label": "Application",
      "name": "Application Server",
      "properties": {}
    },
    {
      "key": "credential:db-app",
      "label": "Credential",
      "name": "Application Database Credential",
      "properties": {
        "credential_material_stored": false
      }
    },
    {
      "key": "sensitive:database",
      "label": "SensitiveAsset",
      "name": "Lab Database",
      "properties": {
        "critical": true,
        "high_value": true
      }
    }
  ],
  "edges": [
    {
      "source_key": "scenario:kali-lab-attacker",
      "target_key": "asset:web",
      "relationship_type": "REACHABLE_FROM",
      "evidence_status": "confirmed",
      "confidence": "confirmed",
      "source": "VulnForge reachability evidence",
      "details": {}
    },
    {
      "source_key": "asset:web",
      "target_key": "service:http",
      "relationship_type": "EXPOSES",
      "evidence_status": "confirmed",
      "confidence": "confirmed",
      "source": "VulnForge service enumeration",
      "details": {}
    },
    {
      "source_key": "service:http",
      "target_key": "vuln:lab-web",
      "relationship_type": "HAS_VULNERABILITY",
      "evidence_status": "supported",
      "confidence": "high confidence",
      "source": "VulnForge vulnerability evidence",
      "details": {}
    },
    {
      "source_key": "vuln:lab-web",
      "target_key": "application:app01",
      "relationship_type": "ENABLES",
      "evidence_status": "theoretical",
      "confidence": "medium confidence",
      "source": "attack graph reasoning",
      "details": {}
    },
    {
      "source_key": "application:app01",
      "target_key": "credential:db-app",
      "relationship_type": "HAS_CREDENTIAL",
      "evidence_status": "confirmed",
      "confidence": "confirmed",
      "source": "VulnForge secret exposure evidence",
      "details": {}
    },
    {
      "source_key": "credential:db-app",
      "target_key": "sensitive:database",
      "relationship_type": "AUTHENTICATES_TO",
      "evidence_status": "supported",
      "confidence": "medium confidence",
      "source": "configuration evidence",
      "details": {
        "privilege_increase": false
      }
    }
  ]
}
```

Because not every edge is confirmed, any resulting path remains theoretical.

## Path calculation

POST `/api/v1/attack-graph/runs/{sync_run_id}/paths`

Example:

```json
{
  "scenario": "kali_lab_attacker",
  "start_node_key": "scenario:kali-lab-attacker",
  "destination_node_key": "sensitive:database",
  "max_depth": 8,
  "only_high_value_destinations": false
}
```

## History APIs

GET `/api/v1/attack-graph/runs`

GET `/api/v1/attack-graph/paths`

GET `/api/v1/attack-graph/paths/{path_id}/evidence`

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1

alembic upgrade head
alembic current
```

Expected:

`0016_neo4j_attack_graph (head)`

## Tests

```powershell
pytest -v tests/test_attack_graph_validation.py
pytest -v tests/test_attack_path_analyzer.py
pytest -v tests/test_attack_graph_scenarios.py
pytest -v
```

## Run

Start native Neo4j first, then:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected API version:

`0.16.0`

Expected Swagger group:

`neo4j-attack-graph`

## Safety boundary

V16 is a graph-analysis layer.

It does not:

- execute exploits
- execute PoCs
- perform credential replay
- perform lateral movement
- bypass authentication
- compromise systems to confirm an edge
- turn theoretical relationships into confirmed evidence automatically

Only evidence from prior authorized observations may mark graph edges as confirmed.
