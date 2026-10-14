# VulnForge AI 2.0 — Final Frontend Integration Pack

This is **not V21**. The project milestone sequence still ends at V20.

The purpose of this pack is to complete the frontend and lab-integration gap that remained
after the V20 backend implementation.

## What this pack fixes

Before this integration, V6–V20 were primarily visible through:

- FastAPI Swagger
- PostgreSQL
- Neo4j Browser
- pytest
- report API downloads

This pack adds a React UI for those modules while preserving the existing V1–V5 lab workspace.

## Workspace switch

The application now has two frontend workspaces:

### V1–V5 Lab

Preserves the existing UI for:

- networks
- assets
- scan scopes
- profiles
- tags
- credentials
- target validation
- discovery
- service enumeration
- exposure findings
- fingerprinting
- authenticated assessment
- audit

### V6–V20 Platform

Adds UI coverage for:

- Exposure Overview
- SBOM / Packages
- Vulnerability Intelligence
- CWE / CAPEC / ATT&CK context
- Severity Analysis
- Configuration Weaknesses
- Web Security
- TLS Security
- Secret Exposure
- Patch / EOL
- Exploitability
- Neo4j Attack Paths
- Environmental Risk
- Security Controls / Residual Risk
- Grounded AI Analyst
- Remediation / Verification
- Final Evaluation
- Reports
- VMware Lab Validation

## Visualization libraries

The final frontend uses:

- ECharts for risk trends
- Cytoscape.js for attack-path visualization

Install:

```powershell
cd "F:\My_Projects\Vulnforge\frontend"

npm install axios echarts cytoscape
npm install -D @types/cytoscape
```

## Environment

Create or update:

`frontend/.env`

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

## Run

Terminal 1 — PostgreSQL

Use your existing PostgreSQL 18 Windows service.

Terminal 2 — Neo4j

```powershell
cd "$env:NEO4J_HOME\bin"
.\neo4j.bat console
```

Terminal 3 — FastAPI

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1

uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Terminal 4 — React

```powershell
cd "F:\My_Projects\Vulnforge\frontend"

npm install
npm run dev
```

Open the Vite URL, normally:

`http://localhost:5173`

## Important design decision

The V1–V5 interface is preserved in `LegacyV1V5Workspace.tsx`.

This avoids discarding working lab functions while allowing the V6–V20 platform to use a cleaner
navigation structure.

## Frontend API mapping

| Frontend area | Backend source |
| --- | --- |
| Exposure Overview | `/dashboard/final`, `/environmental-risk/scores` |
| SBOM | `/sbom/imports` |
| Vulnerability Intelligence | `/threat-intel/*` |
| CWE/CAPEC/ATT&CK | `/weakness-context/*` |
| Severity | `/severity/analyses` |
| Configuration | `/config-assessment/runs` |
| Web | `/web-assessment/imports` |
| TLS | `/tls-assessment/imports` |
| Secrets | `/secret-exposure/imports` |
| Patch/EOL | `/patch-lifecycle/runs` |
| Exploitability | `/exploitability/assessments` |
| Attack Graph | `/attack-graph/runs`, `/attack-graph/paths` |
| Environmental Risk | `/environmental-risk/*` |
| Security Controls | `/security-controls/*` |
| Grounded Analyst | `/analyst/*` |
| Remediation | `/remediation/*` |
| Final Evaluation | `/evaluation/*` |
| Reports | `/reports/generate` |
| VMware validation | V1–V5 scan/evidence endpoints |

## Important limitation

The frontend does not bypass evidence controls.

Network actions still go through backend ScanScope and authorization validation.
The UI cannot turn an out-of-scope target into an approved target.

Attack graphs remain analytical.
The interface never claims exploit success merely because a graph path exists.

The AI analyst continues to use structured evidence and deterministic grounding rules.
