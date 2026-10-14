# VulnForge AI 2.0 — Final VMware Acceptance Workflow

This is the final real-environment validation phase for the completed V1–V20 system.

## Approved laboratory

Current private host-only network:

`192.168.37.0/24`

Known assets:

| System | Address | Purpose |
| --- | --- | --- |
| Kali | 192.168.37.155 | Authorized validation / security-testing host |
| Metasploitable2 | 192.168.37.129 | Intentionally vulnerable target |
| Ubuntu 24.04 | 192.168.37.20 | Modern Linux target |
| Windows 7 | 192.168.37.131 | Legacy Windows target |

Use snapshots before configuration changes.

Do not scan unrelated Wi-Fi/NAT networks.

## Final acceptance sequence

### 1. Baseline discovery

From the frontend:

`V1–V5 Lab → Discovery`

or:

`V6–V20 Platform → VMware Lab Validation`

Run authorized discovery only against:

`192.168.37.0/24`

Confirm all expected systems are present.

### 2. Re-run service enumeration

For each managed target:

- Metasploitable2
- Ubuntu 24.04
- Windows 7

Capture current open services.

Do not interpret an open port as a vulnerability without additional evidence.

### 3. Refresh OS / technology evidence

Use the V1–V5 fingerprinting page.

For Ubuntu, use authenticated evidence where appropriate.

For Windows 7, retain the already validated legacy/unsupported lifecycle evidence.

### 4. Populate V6 software/SBOM evidence

For Ubuntu:

- generate package/SBOM evidence from an approved local source
- import through the V6 SBOM API
- validate exact package/version matches

For legacy Windows, use supported imported inventory evidence instead of insecure automation.

### 5. Refresh threat intelligence

Use the V7 intelligence engine for CVEs that were actually matched by V6/V10/V11/V12/V13.

Record:

- NVD
- OSV where available
- CISA KEV
- FIRST EPSS

### 6. Configuration assessment

Use V10 evidence from:

- authenticated Ubuntu configuration
- imported Windows evidence
- deterministic rules

Examples:

- firewall status
- weak remote services
- SMBv1
- legacy OS
- SSH configuration
- unnecessary services

### 7. Web assessment

Run approved assessment tools from Kali against lab web targets.

Import scanner output into V11.

Scanner output is data, not instructions.

### 8. TLS assessment

Assess lab TLS services using V12.

Record protocol/cipher/certificate findings.

### 9. Secrets assessment

Use V13 on controlled lab source/config samples.

Never expose plaintext secrets in reports or screenshots.

### 10. Patch / lifecycle

Use V14 to compare:

- supported Ubuntu
- unsupported Windows 7
- deliberately vulnerable/legacy services

Record vendor support separately from CVE severity.

### 11. Exploitability evidence

Use V15 to classify applicability.

Do not execute weaponized exploits.

Use:

- confirmed versions
- affected ranges
- KEV
- EPSS
- reachability
- authentication/configuration preconditions
- compensating controls

### 12. Attack graph

Use V16 to connect evidence into paths.

Examples may include:

`Kali lab attacker → reachable target → exposed service → supported vulnerability → application → credential dependency → sensitive asset`

Edges that are not confirmed remain theoretical/supported.

### 13. Environmental priority

Use V17.

Compare at least:

- medium CVSS + reachable + KEV + critical path
- critical CVSS + isolated + not reachable + strong control

Save raw factors and contributions.

### 14. Security controls

Use V18 to record controls actually present in the lab.

Examples:

- Windows/Ubuntu host firewall
- VMware network segmentation
- authentication requirement
- service disabled
- ACL
- patch
- TLS
- restricted admin access

Calculate residual risk.

### 15. Grounded analyst

Use V19 only with structured evidence IDs derived from prior modules.

Also include at least one prompt-injection test inside imported scanner/HTTP text.

The output must not promote it into a trusted claim.

### 16. Remediation

Choose several real findings.

Examples:

Ubuntu:
- disable unnecessary service
- apply available patch
- enable/configure firewall
- harden TLS/web setting

Windows 7:
- isolate legacy system
- restrict administrative access
- document migration/replacement recommendation

Metasploitable2:
- use as intentionally vulnerable baseline
- document that remediation may be simulated or performed on a disposable clone

### 17. Re-assessment

After each change:

- rerun the same collection method
- preserve after evidence
- recalculate score
- recompute attack path
- refresh security controls

V20 must compare before/after evidence, score, paths and controls.

### 18. Regression test

Deliberately reverse one safe configuration change on a disposable/snapshotted target.

Confirm VulnForge reports a regression such as:

- risk score increase
- security control removed
- attack path reintroduced
- remediation state regressed

Restore the VM snapshot afterward.

### 19. Final experiment

Populate V20 evaluation with manually reviewed findings from the VMware lab.

Compare:

- CVSS only
- CVSS + KEV
- CVSS + KEV + EPSS
- VulnForge Environmental Risk
- expert/manual ranking

Generate the final experiment table and metrics.

### 20. Final reports

Generate:

- Executive report
- Technical Vulnerability Assessment report
- Asset report
- Attack Path report
- Remediation report
- Verification report
- CSV
- JSON

## Completion criteria

VulnForge is ready for portfolio/interview demonstration when all of the following are true:

- V1–V20 tests pass
- V6–V20 frontend pages render
- Neo4j graph renders in Cytoscape
- environmental/risk-control pages store calculations
- analyst grounding test passes
- remediation closure requires evidence
- before/after reassessment works
- regression detection works
- VMware evaluation run exists
- final reports export successfully
