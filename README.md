# VulnForge AI 2.0

**AI-Powered Continuous Exposure, Exploitability, Attack-Path & Remediation Engineering Platform**

VulnForge AI 2.0 is an evidence-driven cybersecurity platform designed to answer a practical question:

> **What weaknesses exist in this environment, which ones are realistically applicable, how do they combine into meaningful attack paths, what should be remediated first, and can we prove that remediation reduced risk?**

The platform combines vulnerability assessment, exposure management, authenticated evidence, SBOM analysis, threat intelligence, attack-path analysis, environmental risk scoring, security-control awareness, grounded AI analysis, remediation engineering, reassessment, regression detection, dashboards, and security reporting.

The project is designed for a **controlled VMware Workstation laboratory** and intentionally avoids automatic exploitation.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Why VulnForge Exists](#why-vulnforge-exists)
- [Key Security Principles](#key-security-principles)
- [Main Features](#main-features)
- [V1-V20 Capability Map](#v1-v20-capability-map)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Repository Structure](#repository-structure)
- [Requirements](#requirements)
- [Native Windows Setup](#native-windows-setup)
- [PostgreSQL Setup](#postgresql-setup)
- [Neo4j Setup](#neo4j-setup)
- [Backend Setup](#backend-setup)
- [Frontend Setup](#frontend-setup)
- [Environment Variables](#environment-variables)
- [VMware Lab Setup](#vmware-lab-setup)
- [Lab Machine Details](#lab-machine-details)
- [How to Run the Full System](#how-to-run-the-full-system)
- [Frontend Workflow](#frontend-workflow)
- [Complete A-to-Z Security Workflow](#complete-a-to-z-security-workflow)
- [Real VMware Validation Workflow](#real-vmware-validation-workflow)
- [Testing](#testing)
- [Important API Areas](#important-api-areas)
- [Environmental Risk Scoring](#environmental-risk-scoring)
- [Attack Graph](#attack-graph)
- [Grounded AI Analyst](#grounded-ai-analyst)
- [Remediation and Verification](#remediation-and-verification)
- [Final Evaluation](#final-evaluation)
- [Reports](#reports)
- [Security Boundaries](#security-boundaries)
- [Troubleshooting](#troubleshooting)
- [Interview Demonstration Flow](#interview-demonstration-flow)
- [Real-World Benefits](#real-world-benefits)
- [Known Limitations](#known-limitations)
- [Future Improvements](#future-improvements)
- [Project Status](#project-status)
- [Author](#author)

---

# Project Overview

VulnForge AI 2.0 is not just a vulnerability scanner.

It is a complete **security decision-engineering platform** that starts with raw evidence and continues until remediation is verified.

The platform integrates:

- Asset discovery
- Network enumeration
- Service fingerprinting
- OS and technology fingerprinting
- Authenticated Windows/Linux assessment
- SBOM and package inventory
- CVE matching
- NVD intelligence
- OSV intelligence
- CISA KEV
- FIRST EPSS
- CWE mapping
- CAPEC mapping
- MITRE ATT&CK context
- CVSS v3.1 / CVSS v4 analysis
- Configuration assessment
- Web security assessment
- TLS security assessment
- Secret exposure analysis
- Patch and lifecycle risk
- Exploitability evidence
- Neo4j attack-path analysis
- Environmental risk scoring
- Security-control awareness
- Residual risk calculation
- Grounded AI analysis
- Remediation workflow
- Before/after reassessment
- Regression detection
- Final dashboards
- PDF / CSV / JSON reporting
- Evaluation against expert/manual prioritization

---

# Why VulnForge Exists

Traditional vulnerability-management workflows often produce too many findings and rely too heavily on CVSS.

A vulnerability with a high CVSS score may be unreachable, isolated, already mitigated, patched through a vendor backport, not applicable to the installed version, protected by strong controls, or irrelevant to a critical attack path.

At the same time, a medium-severity issue may be reachable, listed in CISA KEV, highly probable according to EPSS, present on a critical asset, connected to exposed credentials, and part of an important attack path.

VulnForge improves this process by combining **technical severity + local evidence + environmental context + attack paths + controls + lifecycle + verification**.

---

# Key Security Principles

1. **Evidence before conclusion**
2. **Never automatically execute exploits**
3. **Never scan outside approved laboratory CIDRs**
4. **Validate scope before every active network action**
5. **Treat imported scanner output as untrusted data**
6. **Do not invent CVEs, versions, patches, fixes, or attack paths**
7. **Do not treat an open port as automatically vulnerable**
8. **Do not treat an ATT&CK mapping as proof that an attack occurred**
9. **Do not treat a security control as proof that a vulnerability is fixed**
10. **Require reassessment evidence before verified closure**
11. **Use `insufficient evidence` when facts are unavailable**
12. **Preserve evidence provenance and confidence**

---

# Main Features

## Exposure Management

- Asset inventory
- Approved scan scope
- Network discovery
- Service enumeration
- Exposure identification
- OS/application fingerprinting

## Authenticated Assessment

- SSH-based Linux collection
- Windows evidence import / authorized remote collection
- Encrypted credential profiles
- Failed-authentication protection
- Lockout tracking
- Authenticated vs unauthenticated confidence comparison

## Vulnerability Intelligence

- NVD
- OSV
- CISA KEV
- FIRST EPSS
- CVSS
- CWE
- CPE
- Fixed / affected ranges
- Source provenance
- Intelligence freshness
- Conflict tracking

## Vulnerability Applicability

- Exact package/version matching
- PURL
- CPE
- Ecosystem matching
- Vendor backport handling
- Exploitability evidence
- Reachability
- Authentication requirements
- Configuration prerequisites
- Compensating controls

## Attack-Path Analysis

Neo4j models relationships between networks, assets, services, applications, accounts, credentials, vulnerabilities, configuration findings, secret findings, security controls, sensitive assets, user roles, and trust boundaries.

## Risk Engineering

VulnForge calculates contextual risk using CVSS, exploit probability, known exploitation, network exposure, reachability, asset criticality, attack-path importance, privilege impact, credential exposure, security-control strength, patch availability, threat relevance, evidence confidence, and lifecycle risk.

## Grounded AI

The AI analyst receives structured evidence, cites evidence IDs, does not invent CVEs or fixes, treats imported narrative as untrusted, emits `insufficient evidence` when required, and provides deterministic fallback behavior.

## Remediation Engineering

Every remediation case can contain root cause, technical remediation, temporary mitigation, affected assets, owner, SLA, priority, due date, verification procedure, rollback notes, and expected risk reduction.

Workflow:

```text
Open
  ↓
Triaged
  ↓
Assigned
  ↓
Remediation In Progress
  ↓
Ready for Verification
  ↓
Verified
  ↓
Closed
```

Alternative states:

```text
Accepted Risk
False Positive
Deferred
```

---

# V1-V20 Capability Map

| Milestone | Capability |
|---|---|
| V1 | Security lab foundation, assets, networks, scan scopes, profiles, credentials, audit |
| V2 | Network asset discovery and reconciliation |
| V3 | Port/service enumeration and exposure findings |
| V4 | OS and technology fingerprinting |
| V5 | Authenticated Windows/Linux assessment |
| V6 | SBOM and package vulnerability analysis |
| V7 | NVD / OSV / CISA KEV / FIRST EPSS intelligence |
| V8 | CWE / CAPEC / MITRE ATT&CK context |
| V9 | CVSS v3.1 and CVSS v4 analysis |
| V10 | Configuration and baseline assessment |
| V11 | Web application assessment |
| V12 | TLS security assessment |
| V13 | Secret exposure assessment |
| V14 | Patch and lifecycle risk |
| V15 | Exploitability evidence |
| V16 | Neo4j attack graph |
| V17 | Environmental Risk Score 2.0 |
| V18 | Security-control awareness and residual risk |
| V19 | Grounded VulnForge AI Analyst |
| V20 | Remediation, verification, dashboards, evaluation and reports |

---

# Technology Stack

## Backend
- Python
- FastAPI
- SQLAlchemy
- Alembic
- Pydantic
- psycopg
- pytest
- httpx

## Frontend
- React
- TypeScript
- Vite
- Axios
- ECharts
- Cytoscape.js

## Databases
- PostgreSQL 18
- Neo4j Community 5.x

## Security Tooling
- Nmap / Npcap
- Wireshark / TShark
- WhatWeb
- Nikto
- OWASP ZAP
- Nuclei
- Syft
- Trivy
- Grype
- OpenSSL
- testssl.sh / sslscan
- Lynis / OpenSCAP
- PowerShell
- SSH

## Threat Intelligence
- NVD
- OSV
- CISA Known Exploited Vulnerabilities
- FIRST EPSS

## Security Frameworks / Models
- CVSS v3.1
- CVSS v4
- CWE
- CAPEC
- MITRE ATT&CK
- OWASP concepts

---

# System Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                    React + TypeScript UI                     │
│                                                            │
│ V1-V5 Lab Workspace        V6-V20 Platform Workspace        │
└───────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                          FastAPI                             │
│ APIs • validation • evidence processing • risk • workflow   │
└───────────────────────┬───────────────────┬──────────────────┘
                        │                   │
                        ▼                   ▼
             ┌─────────────────┐   ┌─────────────────┐
             │   PostgreSQL    │   │      Neo4j      │
             │ Evidence        │   │ Attack Graph    │
             │ Findings        │   │ Relationships   │
             │ Risk            │   │ Attack Paths    │
             │ Remediation     │   │ Reachability    │
             │ Evaluation      │   │ Trust           │
             └────────┬────────┘   └────────┬────────┘
                      │                     │
                      └──────────┬──────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────┐
│                     Evidence Sources                         │
│ Nmap • SSH • SBOM • Web • TLS • Config • Threat Intel       │
└───────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                  VMware Workstation Lab                     │
│ Kali • Metasploitable2 • Ubuntu 24.04 • Windows 7           │
└──────────────────────────────────────────────────────────────┘
```

---

# Repository Structure

```text
Vulnforge/
│
├── backend/
│   ├── alembic/
│   │   └── versions/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/routes/
│   │   ├── core/
│   │   ├── db/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── main.py
│   ├── tests/
│   ├── requirements.txt
│   ├── requirements-v20.txt
│   └── .env
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── lib/
│   │   ├── pages/
│   │   ├── App.tsx
│   │   ├── LegacyV1V5Workspace.tsx
│   │   ├── PostV5Workspace.tsx
│   │   └── styles.css
│   ├── package.json
│   ├── .env
│   └── vite.config.ts
│
├── docs/
│   └── ...
│
└── README.md
```

---

# Requirements

Recommended Windows host:

- Windows 10 / 11
- VMware Workstation Pro 17
- PowerShell
- Git
- Python
- Node.js
- PostgreSQL 18
- Java 21
- Neo4j Community Edition
- Nmap + Npcap

Current local services:

```text
PostgreSQL  127.0.0.1:5433
Neo4j Bolt  127.0.0.1:7687
Neo4j HTTP  127.0.0.1:7474
FastAPI     127.0.0.1:8000
React/Vite  localhost:5173
```

---

# Native Windows Setup

> VulnForge uses a **no-Docker architecture**.

Everything runs natively:

- PostgreSQL → Windows service
- Neo4j → native Java/Neo4j installation
- FastAPI → Python virtual environment
- React → Node/Vite
- Security tools → Windows host / VMware VMs

---

# PostgreSQL Setup

Check service:

```powershell
Get-Service postgresql-x64-18
```

Start if required:

```powershell
Start-Service postgresql-x64-18
```

Check port:

```powershell
Test-NetConnection 127.0.0.1 -Port 5433
```

Database configuration:

```text
Database: vulnforge
User: vulnforge_user
Host: 127.0.0.1
Port: 5433
```

Never commit passwords into Git.

---

# Neo4j Setup

Requirements:

- Java 21
- Neo4j Community 5.x

Example installation:

```text
C:\neo4j\neo4j-community-5.26.32
```

Start:

```powershell
cd "C:\neo4j\neo4j-community-5.26.32\bin"
.\neo4j.bat console
```

Or:

```powershell
cd "$env:NEO4J_HOME\bin"
.\neo4j.bat console
```

Verify:

```powershell
Test-NetConnection 127.0.0.1 -Port 7687
Test-NetConnection 127.0.0.1 -Port 7474
```

Neo4j Browser:

```text
http://localhost:7474
```

---

# Backend Setup

```powershell
cd "F:\My_Projects\Vulnforge\backend"
```

Create venv if required:

```powershell
py -m venv .venv
```

Activate:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install:

```powershell
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-v20.txt
```

Apply migrations:

```powershell
alembic upgrade head
alembic current
```

Expected final migration:

```text
0020_remediation_and_evaluation (head)
```

Run:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health:

```text
http://127.0.0.1:8000/health
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

---

# Frontend Setup

```powershell
cd "F:\My_Projects\Vulnforge\frontend"
```

Install:

```powershell
npm install
npm install axios echarts cytoscape
npm install -D @types/cytoscape
```

Run:

```powershell
npm run dev
```

Open:

```text
http://localhost:5173
```

---

# Environment Variables

## Backend `.env`

```env
APP_NAME=VulnForge AI 2.0
APP_ENV=development
APP_HOST=127.0.0.1
APP_PORT=8000

DATABASE_URL=postgresql+psycopg://vulnforge_user:CHANGE_ME@127.0.0.1:5433/vulnforge

CORS_ORIGINS=http://localhost:5173

NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe

NEO4J_URI=bolt://127.0.0.1:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=CHANGE_ME

VULNFORGE_CREDENTIAL_KEY=GENERATE_AND_STORE_SECURELY
VULNFORGE_SECRET_FINGERPRINT_KEY=GENERATE_AND_STORE_SECURELY
```

Do not commit `.env` secrets.

## Frontend `.env`

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

---

# VMware Lab Setup

```text
VMware Network: VMnet1 Host-Only
CIDR: 192.168.37.0/24
Windows Host Adapter: 192.168.37.1
```

Only this approved private host-only network should be used for active validation.

---

# Lab Machine Details

| Machine | Hostname | OS | IP | MAC | Role |
|---|---|---|---|---|---|
| Kali | `kali` | Kali Linux | `192.168.37.155` | `00:0C:29:44:5D:F4` | Authorized security-testing host |
| Metasploitable2 | `metasploitable` | Metasploitable 2 | `192.168.37.129` | `00:0C:29:67:87:57` | Intentionally vulnerable target |
| Ubuntu | `ubuntu2404` | Ubuntu 24.04.4 LTS | `192.168.37.20` | `00:0C:29:C5:43:F3` | Modern Linux / remediation target |
| Windows 7 | `Win7-PC` | Windows 7 | `192.168.37.131` | `00:0C:29:C1:28:02` | Legacy lifecycle target |

---

# How to Run the Full System

Use four terminals.

## Terminal 1 — PostgreSQL

```powershell
Get-Service postgresql-x64-18
```

## Terminal 2 — Neo4j

```powershell
cd "$env:NEO4J_HOME\bin"
.\neo4j.bat console
```

## Terminal 3 — Backend

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Terminal 4 — Frontend

```powershell
cd "F:\My_Projects\Vulnforge\frontend"
npm run dev
```

Then start the VMware VMs.

---

# Frontend Workflow

## V1-V5 Lab Workspace

```text
Dashboard
Networks
Assets
Scopes
Profiles
Tags
Credentials
Validator
Discovery
Services
Exposures
Fingerprinting
Authenticated
Audit
```

## V6-V20 Platform Workspace

```text
Exposure Overview
SBOM / Packages
Vulnerability Intelligence
CWE / CAPEC / ATT&CK
Severity Analysis
Configuration Weaknesses
Web Security
TLS Security
Secrets
Patch / EOL
Exploitability
Attack Paths
Environmental Risk
Security Controls
Grounded AI Analyst
Remediation / Verification
Final Evaluation
Reports
VMware Lab Validation
```

---

# Complete A-to-Z Security Workflow

```text
Authorized Scope
      ↓
Asset Discovery
      ↓
Service Enumeration
      ↓
OS / Technology Fingerprinting
      ↓
Authenticated Inventory
      ↓
SBOM / Software Inventory
      ↓
Package-to-Vulnerability Matching
      ↓
NVD / OSV / KEV / EPSS Enrichment
      ↓
CWE / CAPEC / ATT&CK Context
      ↓
CVSS Analysis
      ↓
Configuration Assessment
      ↓
Web Assessment
      ↓
TLS Assessment
      ↓
Secret Exposure
      ↓
Patch / Lifecycle Analysis
      ↓
Exploitability Evidence
      ↓
Neo4j Attack Graph
      ↓
Environmental Risk Score
      ↓
Security Controls
      ↓
Residual Risk
      ↓
Grounded AI Analyst
      ↓
Remediation Case
      ↓
Real Defensive Change
      ↓
Re-Assessment
      ↓
Before / After Comparison
      ↓
Risk Delta
      ↓
Attack-Path Change
      ↓
Control Change
      ↓
Verification
      ↓
Regression Detection
      ↓
Final Evaluation
      ↓
Reports
```

---

# Real VMware Validation Workflow

1. Take VMware snapshots before changes.
2. Validate the target using the approved `192.168.37.0/24` ScanScope.
3. Run ARP discovery.
4. Enumerate services on Ubuntu, Metasploitable2, and Windows 7.
5. Run OS/technology fingerprinting.
6. Run authenticated Ubuntu assessment.
7. Generate/import package/SBOM evidence.
8. Enrich matched vulnerabilities with NVD/OSV/KEV/EPSS.
9. Import configuration evidence.
10. Import authorized web/TLS/secret assessment evidence.
11. Evaluate patch/lifecycle state.
12. Calculate exploitability.
13. Build the Neo4j attack graph.
14. Calculate environmental risk.
15. Register controls and calculate residual risk.
16. Run the grounded analyst.
17. Create remediation case.
18. Apply a real defensive lab change.
19. Repeat the same assessment method.
20. Run before/after reassessment.
21. Verify risk/path/control changes.
22. Add closure evidence.
23. Run final evaluation.
24. Generate reports.

---

# Environmental Risk Scoring

| Factor | Weight |
|---|---:|
| Technical severity | 12% |
| Exploit probability | 9% |
| Known exploitation | 10% |
| Network exposure | 8% |
| Reachability | 8% |
| Asset criticality | 10% |
| Attack-path importance | 10% |
| Privilege impact | 6% |
| Credential exposure | 6% |
| Security-control weakness | 5% |
| Patch unavailability | 5% |
| Threat relevance | 4% |
| Evidence confidence | 3% |
| Lifecycle risk | 4% |

Priority tiers:

```text
P0 >= 85
P1 >= 70
P2 >= 50
P3 >= 30
P4 < 30
```

---

# Attack Graph

V16 uses Neo4j to model security relationships.

Node types include:

```text
Network
Asset
Service
Application
Account
Credential
Vulnerability
ConfigFinding
SecretFinding
SecurityControl
SensitiveAsset
UserRole
TrustBoundary
```

Relationship examples:

```text
CONNECTED_TO
EXPOSES
RUNS
HAS_VULNERABILITY
USES_ACCOUNT
HAS_CREDENTIAL
CAN_ACCESS
TRUSTS
REACHABLE_FROM
PROTECTED_BY
ENABLES
AFFECTS
MEMBER_OF
AUTHENTICATES_TO
```

A graph path is not proof of successful exploitation.

---

# Grounded AI Analyst

V19 accepts structured evidence and returns grounded JSON.

The analyst must not invent:

- CVEs
- versions
- fixes
- exploitability
- ATT&CK mappings
- attack paths
- business impact

When information is unavailable:

```text
insufficient evidence
```

Imported scanner text, HTTP content, package descriptions, CVE descriptions, and report text are treated as untrusted data.

---

# Remediation and Verification

Verification process:

1. Create remediation case
2. Apply defensive change
3. Repeat original evidence collection
4. Preserve after-evidence
5. Recalculate risk
6. Recalculate attack path
7. Compare controls
8. Run reassessment
9. Add closure evidence
10. Move to Verified / Closed

Regression detection can identify:

```text
risk_score_increased
new_attack_path_introduced
security_control_removed
remediation_state_regressed
```

---

# Final Evaluation

V20 compares:

```text
CVSS-only
CVSS + KEV
CVSS + KEV + EPSS
VulnForge Environmental Risk
Expert / Manual Ranking
```

Recommended dataset:

```text
15–30 manually reviewed findings
```

Metrics include:

- applicability precision,
- false-positive rate,
- top-k priority agreement,
- KEV prioritization,
- attack-path relevance,
- time-to-triage,
- remediation risk reduction,
- AI factual accuracy,
- unsupported-claim rate,
- security-rule accuracy,
- verification success.

---

# Reports

Supported reports:

```text
Executive Report
Technical Vulnerability Assessment Report
Asset Report
Attack Path Report
Remediation Report
Verification Report
```

Formats:

```text
PDF
CSV
JSON
```

---

# Important API Areas

Swagger:

```text
http://127.0.0.1:8000/docs
```

Major API groups:

```text
/api/v1/security-lab
/api/v1/scans
/api/v1/fingerprints
/api/v1/authenticated
/api/v1/sbom
/api/v1/threat-intel
/api/v1/weakness-context
/api/v1/severity
/api/v1/config-assessment
/api/v1/web-assessment
/api/v1/tls-assessment
/api/v1/secret-exposure
/api/v1/patch-lifecycle
/api/v1/exploitability
/api/v1/attack-graph
/api/v1/environmental-risk
/api/v1/security-controls
/api/v1/analyst
/api/v1/remediation
/api/v1/evaluation
/api/v1/dashboard
/api/v1/reports
```

---

# Testing

Backend:

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1
pytest -v
```

Final V20 tests:

```powershell
pytest -v tests/test_remediation_workflow.py
pytest -v tests/test_reassessment_engine.py
pytest -v tests/test_evaluation_engine.py
pytest -v tests/test_report_service.py
```

Frontend:

```powershell
cd "F:\My_Projects\Vulnforge\frontend"
npm run build
```

---

# Security Boundaries

VulnForge is intended only for systems you own or are explicitly authorized to assess.

Do not use the platform against unauthorized external systems.

The project intentionally avoids automatic exploitation.

---

# Troubleshooting

## PostgreSQL connection refused

```powershell
Get-Service postgresql-x64-18
Test-NetConnection 127.0.0.1 -Port 5433
```

## Neo4j unavailable

```powershell
Test-NetConnection 127.0.0.1 -Port 7687
```

Start:

```powershell
cd "$env:NEO4J_HOME\bin"
.\neo4j.bat console
```

## Frontend cannot reach backend

Frontend `.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

Ensure backend CORS permits:

```text
http://localhost:5173
```

## Nmap not found

Expected path:

```text
C:\Program Files (x86)\Nmap\nmap.exe
```

Verify:

```powershell
& "C:\Program Files (x86)\Nmap\nmap.exe" --version
```

---

# Interview Demonstration Flow

A strong 5–10 minute demonstration:

1. Open VulnForge.
2. Explain V1–V5 Lab vs V6–V20 Platform.
3. Show approved VMnet1 scope.
4. Show VMware asset inventory.
5. Show real discovery/service evidence.
6. Show authenticated Ubuntu evidence.
7. Show vulnerability intelligence.
8. Show exploitability classification.
9. Show Neo4j attack path.
10. Compare CVSS with Environmental Risk.
11. Show a control reducing residual risk.
12. Show Grounded AI Analyst.
13. Show remediation workflow.
14. Show before/after reassessment.
15. Show risk delta and verification.
16. Finish with dashboard and reports.

---

# Real-World Benefits

## Security Engineering
- Evidence-backed decisions
- Better exposure prioritization
- Attack-path visibility
- Remediation engineering

## Vulnerability Management
- Reduced false-positive burden
- Context beyond CVSS
- KEV/EPSS enrichment
- Lifecycle awareness
- Verified closure

## Purple Team
- Controlled validation
- Reachability and attack-path reasoning
- Defensive remediation
- No automatic exploitation required

## SOC / Security Operations
- Unified evidence
- ATT&CK context
- Grounded analysis
- Risk-aware remediation

## Management
- Risk trends
- Prioritized remediation
- Verification outcomes
- Executive reporting

---

# Known Limitations

VulnForge is a research / portfolio security-engineering platform rather than a commercial enterprise exposure-management product.

Current limitations include:

- some later workflows use structured JSON inputs,
- some cross-module evidence selection remains manual,
- V17 scoring weights require broader calibration,
- evaluation currently focuses on a private VMware lab,
- external LLM integration is intentionally optional,
- full enterprise RBAC and multi-tenancy are outside the current scope,
- graph scenario provenance can be strengthened further.

---

# Future Improvements

Potential extensions:

- automated V6–V20 evidence orchestration,
- scheduled continuous assessment,
- SIEM / SOAR integrations,
- richer guided frontend forms,
- enterprise RBAC,
- multi-tenancy,
- KMS / vault-backed secrets,
- asynchronous workers,
- enhanced graph provenance,
- larger labeled evaluation datasets,
- production observability,
- continuous remediation verification.

---

# Project Status

```text
V1-V20 Backend: Complete
Frontend V1-V20 Integration: Complete
PostgreSQL Integration: Complete
Neo4j Attack Graph: Complete
VMware Lab Integration: Complete
Grounded AI Analyst: Complete
Remediation Workflow: Complete
Verification / Regression Engine: Complete
Final Evaluation Framework: Complete
Report Generation: Complete

Final empirical results:
Must be generated from real VMware lab runs.
```

---

# Author

**Gihan Shavinda Rathnayake**

Cybersecurity / Security Engineering / Purple Team

Areas of interest:

- Purple Team Engineering
- Vulnerability Management
- Exposure Management
- Detection Engineering
- Cloud Security
- Attack-Path Analysis
- AI for Cybersecurity
- Security Automation

---

## Final Note

VulnForge AI 2.0 was designed around one core engineering principle:

> **Do not call a security issue understood until the evidence supports the conclusion, and do not call it fixed until reassessment proves that the risk was reduced.**
