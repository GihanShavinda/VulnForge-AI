# VulnForge AI 2.0 — V6 SBOM & Package Vulnerability Assessment

V6 adds SBOM/package ingestion, package normalisation, evidence-preserving vulnerability matching,
import history, and component drift detection.

Supported formats:
- CycloneDX JSON
- SPDX JSON
- Syft JSON
- Trivy JSON
- Grype JSON
- OS package inventory (JSON rows or tab/space-delimited text)

Matching policy:
1. Prefer exact normalised PURL package identity.
2. Otherwise use exact normalised CPE product identity.
3. Name-only matching is allowed only when both sides have the same explicit ecosystem and the
   exact normalised package name.
4. Missing versions never satisfy a version range.
5. Debian/RPM generic range matching fails closed because PEP 440 is not distro version ordering.
6. Scanner-native Trivy/Grype/CycloneDX vulnerability relationships are preserved as source assertions.
7. Explicit vendor status values `not_affected`, `patched`, `fixed`, or `backported` suppress generic matches.

Main APIs:
- POST /api/v1/sbom/imports
- GET /api/v1/sbom/imports
- GET /api/v1/sbom/imports/{import_id}/components
- GET /api/v1/sbom/imports/{import_id}/matches
- GET /api/v1/sbom/imports/{import_id}/drift
- POST /api/v1/sbom/advisories
- GET /api/v1/sbom/advisories

Run:
```powershell
cd F:\My_Projects\Vulnforge\backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
alembic upgrade head
alembic current
pytest -v tests/test_package_vulnerability_matcher.py
pytest -v tests/test_sbom_parsers.py
pytest -v tests/test_component_drift.py
pytest -v
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected migration:
`0006_sbom_package_vulnerability (head)`
