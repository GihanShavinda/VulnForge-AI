# VulnForge AI 2.0 — V14 Patch and Lifecycle Risk

## Purpose

V14 models patch posture and lifecycle risk separately from generic vulnerability severity.

It can represent:

- missing patches
- outdated packages
- unsupported operating systems
- end-of-life applications
- legacy protocols
- obsolete services
- unsupported runtime versions

## New finding types

### PatchFinding

Tracks:

- component
- installed version
- fixed version
- vulnerability identifier
- severity
- risk state
- patch availability
- vendor backport
- reboot requirement where known
- compensating control
- evidence
- remediation

Supported patch-risk states include:

- `vulnerable_patch_available`
- `vulnerable_no_vendor_patch`
- `vendor_backport`
- `temporary_compensating_control`
- `patch_status_unknown`

### LifecycleFinding

Tracks:

- product
- version
- category
- severity
- vendor support status
- end-of-support date
- patch availability
- accepted legacy system
- temporary compensating control
- vendor backport
- replacement recommendation
- evidence

## Accepted legacy systems

An accepted legacy system is not treated as safe.

VulnForge lowers lifecycle severity only when the legacy state is explicitly accepted and,
when available, accompanied by a compensating control such as:

- isolated VMware host-only networking
- restrictive firewall policy
- no Internet access
- dedicated lab-only use
- documented retirement/replacement plan

## Vendor backports

A distribution or vendor may backport a security fix without changing the upstream version
to the version commonly shown in public advisories.

V14 therefore treats `vendor_backport=true` as a distinct state instead of automatically
marking the component as unpatched based only on upstream version comparison.

## Windows XP and Windows 7 lab demonstrations

The built-in lifecycle catalog includes:

### Microsoft Windows XP

- version family: 5.1
- vendor support status: unsupported
- end of support: 2014-04-08
- standard vendor patch availability: unavailable
- default severity: Critical

### Microsoft Windows 7

- version family: 6.1
- vendor support status: unsupported
- end of support: 2020-01-14
- standard vendor patch availability: unavailable
- default severity: Critical

These are lifecycle-risk demonstrations for the VulnForge lab. If retained intentionally,
mark them as accepted legacy systems and document isolation/compensating controls.

## API

### Lifecycle catalog

GET `/api/v1/patch-lifecycle/catalog`

### Lifecycle lookup

GET `/api/v1/patch-lifecycle/catalog/lookup?product=Microsoft%20Windows%207&version=6.1.7601`

### Assess patch and lifecycle observations

POST `/api/v1/patch-lifecycle/assess`

Example:

```json
{
  "asset_id": null,
  "source_name": "v14-validation",
  "patch_observations": [
    {
      "component": "example-runtime",
      "installed_version": "1.0",
      "fixed_version": "1.1",
      "vulnerability_id": "CVE-LAB-0001",
      "severity": "High",
      "patch_available": true,
      "vendor_backport": false,
      "reboot_required": false,
      "compensating_control": null,
      "evidence": {
        "source": "lab validation"
      }
    }
  ],
  "lifecycle_observations": [
    {
      "product": "Microsoft Windows 7",
      "version": "6.1.7601",
      "category": "operating_system",
      "vendor_support_status": "unsupported",
      "end_of_support_date": "2020-01-14",
      "patch_availability": "no_standard_vendor_patch",
      "accepted_legacy_system": true,
      "temporary_compensating_control": "Isolated VMware host-only network with no Internet access.",
      "vendor_backport": false,
      "replacement_recommendation": "Replace with a supported Windows release when no longer needed as a lab target.",
      "evidence": {
        "source": "VulnForge lab inventory"
      }
    }
  ]
}
```

### History

GET `/api/v1/patch-lifecycle/runs`

GET `/api/v1/patch-lifecycle/runs/{run_id}/patch-findings`

GET `/api/v1/patch-lifecycle/runs/{run_id}/lifecycle-findings`

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1
alembic upgrade head
alembic current
```

Expected:

`0014_patch_lifecycle_risk (head)`

## Tests

```powershell
pytest -v tests/test_patch_lifecycle_rules.py
pytest -v tests/test_lifecycle_catalog.py
pytest -v tests/test_patch_lifecycle_schema.py
pytest -v
```

## Run

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected version: `0.14.0`

Expected API group: `patch-lifecycle-risk`
