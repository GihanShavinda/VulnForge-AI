# VulnForge AI 2.0

AI-Powered Vulnerability Assessment, Continuous Exposure, Attack-Path & Remediation Engineering Platform.

## Current milestone

Implemented through **V1 — Security Lab & Network Baseline**.

V1 establishes the safety boundary for all later security assessment features:

- VMware Host-Only lab network design
- Optional isolated NAT path for controlled updates
- Static IP plan
- Asset and network inventory models
- Approved scan scopes
- Target tagging
- Credential profile metadata
- Scan profile safety limits
- Audit logging
- Strict destination scope validation
- Blocking of localhost, multicast, broadcast and out-of-scope targets
- Maintenance-window support
- Evidence-retention settings
- Unit tests for scope-validation edge cases

## Safety model

VulnForge is designed for an authorised private security lab.

The application must never automatically execute weaponised exploits and must never
scan a destination that has not passed scope validation.

Every scanner integration added in later milestones must call the central scope
validator before any scan command is launched.

## Native stack

No Docker is used.

Backend:
- Python 3.12
- FastAPI
- SQLAlchemy
- Alembic
- Pydantic
- PostgreSQL

Graph:
- Neo4j Community Edition

Scheduling:
- APScheduler
- PostgreSQL-backed job records

Frontend:
- React
- TypeScript
- Vite

## V1 repository layout

```text
vulnforge-ai/
├─ backend/
│  ├─ alembic/
│  │  └─ versions/
│  │     └─ 0001_security_lab_baseline.py
│  ├─ app/
│  │  ├─ api/
│  │  │  └─ v1/
│  │  │     └─ routes/
│  │  │        └─ security_lab.py
│  │  ├─ core/
│  │  │  └─ config.py
│  │  ├─ db/
│  │  │  ├─ base.py
│  │  │  └─ session.py
│  │  ├─ models/
│  │  │  └─ security_lab.py
│  │  ├─ schemas/
│  │  │  └─ security_lab.py
│  │  ├─ services/
│  │  │  ├─ audit_service.py
│  │  │  └─ scope_validator.py
│  │  └─ main.py
│  ├─ tests/
│  │  └─ test_scope_validator.py
│  └─ requirements.txt
├─ config/
│  └─ lab_networks.example.yaml
├─ docs/
│  └─ V1_SECURITY_LAB_BASELINE.md
└─ .env.example
```

## Windows setup

Create and activate a Python 3.12 virtual environment:

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Create a PostgreSQL database and user:

```sql
CREATE USER vulnforge_user WITH PASSWORD 'change-me';
CREATE DATABASE vulnforge OWNER vulnforge_user;
```

Copy the environment file:

```powershell
Copy-Item ..\.env.example .env
```

Run migrations:

```powershell
alembic upgrade head
```

Start the API:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Run tests:

```powershell
pytest -q
```

## V1 verification

Before moving to V2, confirm that:

1. The API starts successfully.
2. PostgreSQL migrations complete.
3. The approved Host-Only CIDR exists in the database.
4. A host inside the approved network passes validation.
5. A public or unrelated private IP fails validation.
6. Loopback addresses fail validation.
7. Multicast addresses fail validation.
8. IPv4 broadcast/network addresses fail validation.
9. IPv6 link-local/multicast/loopback addresses fail validation.
10. Scan profiles enforce timeout and concurrency limits.
11. Audit records are written for validation decisions.
12. Vulnerable VMs are reachable only through the intended VMware lab network.

## Important

Do not connect intentionally vulnerable systems such as Windows XP, Windows 7,
Metasploitable2 or vulnerable OWASP targets directly to an untrusted LAN or the
public Internet.

## V1 frontend

The V1 package now includes a React + TypeScript + Vite frontend for:

- Dashboard
- Networks
- Assets
- Scan Scopes
- Scan Profiles
- Asset Tags
- Credential Profiles
- Target Validator
- Audit Logs

Run it with:

```powershell
cd frontend
Copy-Item .env.example .env
npm install
npm run dev
```

Then open `http://localhost:5173`.

---

# V2 — Network Asset Discovery

V2 adds safe Nmap-based network asset discovery to the V1 control plane.

## V2 capabilities

- ICMP host discovery
- ARP host discovery for the local VMware Host-Only segment
- TCP SYN/ACK discovery probes
- Nmap XML ingestion (terminal output is never parsed)
- IP, hostname, MAC and vendor collection
- reachable/missing state
- first-seen and last-seen timestamps
- scan source and scan timestamp
- immutable raw XML evidence with SHA-256 digest
- discovery job tracking
- duplicate reconciliation against manual assets
- detection of new assets, missing assets, IP changes, hostname changes, MAC changes and newly reachable assets
- strict full-target containment inside an enabled `ScanScope`

## V2 endpoints

```text
POST /api/v1/scans/discovery
GET  /api/v1/assets/discovered
GET  /api/v1/scans/{id}/evidence
```

## Nmap requirement

Install Nmap natively on Windows and confirm:

```powershell
nmap --version
Get-Command nmap
```

VulnForge invokes Nmap with argument arrays and `shell=False`. The target is validated before invocation.

## Upgrade from V1

```powershell
cd F:\My_Projects\Vulnforge\backend
.\.venv\Scripts\Activate.ps1
alembic upgrade head
alembic current
pytest -v
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected migration head:

```text
0002_network_asset_discovery (head)
```

Frontend:

```powershell
cd F:\My_Projects\Vulnforge\frontend
npm install
npm run build
npm run dev
```

V2 remains strictly no-Docker.
