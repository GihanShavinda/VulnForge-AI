# VulnForge AI 2.0 — V10 Configuration Vulnerability Assessment

## Purpose

V10 evaluates host configuration evidence using deterministic rules and benchmark profiles.

Supported evidence sources:

- Lynis report-style evidence
- OpenSCAP normalized JSON where applicable
- PowerShell-collected Windows evidence
- custom deterministic control/value evidence

VulnForge does **not** claim CIS certification. Framework references are written as
"CIS concept: ..." and are intended only as alignment/context.

## Finding structure

Every configuration finding contains:

- Control
- ExpectedState
- ObservedState
- Evidence
- Severity
- Remediation
- Confidence
- FrameworkReference

## Benchmark profiles

- Legacy Lab
- Standard Workstation
- Linux Server
- Windows Workstation
- Web Server

The Legacy Lab profile is intentionally tolerant of systems that exist only as
isolated vulnerable targets; findings are still recorded but must be interpreted
in the lab's purpose and network isolation context.

## Linux controls

V10 includes deterministic checks for:

- root SSH login
- password authentication
- weak file permissions
- unnecessary services
- firewall disabled
- insecure sudo configuration
- world-writable files
- legacy protocols
- weak SSH algorithms
- unsafe anonymous services
- unnecessary listening ports

## Windows controls

V10 includes deterministic checks for:

- Guest account
- SMBv1
- weak firewall posture
- RDP/NLA configuration
- unnecessary services
- local administrator exposure
- weak password-policy indicators
- legacy OS
- missing endpoint protections
- anonymous SMB indicators
- weak remote-management configuration

## Important evidence rule

The parsers do not invent a security conclusion.

For example, a Lynis line may be preserved as evidence without automatically
mapping it to a VulnForge control. A finding is created only when a supported
control ID is present and a deterministic rule evaluates the observed state as
insecure.

## API

### Profiles

`GET /api/v1/config-assessment/profiles`

### Assess normalized evidence

`POST /api/v1/config-assessment/assess`

Example Linux assessment:

```json
{
  "asset_id": "YOUR-ASSET-UUID",
  "profile_name": "Linux Server",
  "source_type": "custom-deterministic",
  "source_name": "ubuntu-v10.tsv",
  "evidence": [
    {
      "control_id": "linux.root_ssh_login",
      "category": "ssh",
      "observed_value": "PermitRootLogin yes",
      "source_locator": "sshd -T",
      "confidence": "confirmed",
      "raw": {}
    },
    {
      "control_id": "linux.firewall_enabled",
      "category": "firewall",
      "observed_value": "disabled",
      "source_locator": "ufw status",
      "confidence": "confirmed",
      "raw": {}
    }
  ]
}
```

### Runs

`GET /api/v1/config-assessment/runs`

### Findings

`GET /api/v1/config-assessment/runs/{assessment_id}/findings`

### Evidence

`GET /api/v1/config-assessment/runs/{assessment_id}/evidence`

### Parse Lynis text

`POST /api/v1/config-assessment/parse/lynis`

Body:

```json
{
  "text": "firewall-active=0\nssh-daemon-status=running"
}
```

### Parse OpenSCAP normalized JSON

`POST /api/v1/config-assessment/parse/openscap`

Example:

```json
{
  "results": [
    {
      "id": "xccdf_rule_example",
      "result": "fail",
      "title": "Example check",
      "evidence": "observed value"
    }
  ]
}
```

### Parse PowerShell evidence

`POST /api/v1/config-assessment/parse/powershell`

### Parse simple deterministic evidence

`POST /api/v1/config-assessment/parse/simple-controls`

Input format:

```text
linux.firewall_enabled<TAB>disabled
linux.root_ssh_login<TAB>PermitRootLogin yes
```

## Native Windows collector

Run on an authorized Windows lab host:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\v10_collect_windows_config.ps1
```

The script only gathers local evidence. It does not modify configuration.

## Native Linux collector

Run on an authorized Linux lab host:

```bash
chmod +x ./scripts/v10_collect_linux_config.sh
./scripts/v10_collect_linux_config.sh
```

The script gathers deterministic local evidence only.

## Lynis

Where Lynis is already installed on an authorized Linux lab host:

```bash
sudo lynis audit system --quick
```

Preserve the resulting report and import relevant evidence. Do not automatically
translate every Lynis suggestion into a VulnForge finding.

## OpenSCAP

Use OpenSCAP only where it is appropriate for the installed distribution and
where suitable SCAP content is available. Preserve the original rule identifier,
result, title, and evidence.

VulnForge treats OpenSCAP results as source evidence, not as proof of official
CIS certification.

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1
alembic upgrade head
alembic current
```

Expected:

`0010_configuration_assessment (head)`

## Tests

```powershell
pytest -v tests/test_config_rules.py
pytest -v tests/test_config_evidence_parsers.py
pytest -v tests/test_config_benchmark_catalog.py
pytest -v
```

## Run

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger:

`http://127.0.0.1:8000/docs`

Expected API group:

`configuration-assessment`
