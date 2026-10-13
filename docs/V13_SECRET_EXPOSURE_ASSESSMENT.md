# VulnForge AI 2.0 — V13 Secret Exposure Assessment

V13 detects exposed secrets from Gitleaks output and deterministic scanning of authorized test repositories, configuration files and lab artefacts.

## Supported secret categories

- API key
- private key
- token
- password assignment
- cloud credential pattern
- database connection string
- JWT secret
- SSH private key

## Data minimization

VulnForge never stores or returns complete secrets.

`SecretExposure` stores only:

- secret type
- masked fingerprint
- location
- evidence hash
- severity
- validation status
- first seen
- last seen

The evidence hash is an HMAC-SHA256 value derived with `VULNFORGE_SECRET_FINGERPRINT_KEY`.
This allows duplicate credential detection without retaining the credential.

Set a dedicated development key in `.env`:

```text
VULNFORGE_SECRET_FINGERPRINT_KEY=<generate-a-long-random-value>
```

Do not reuse `VULNFORGE_CREDENTIAL_KEY`.

## False-positive suppression

Obvious placeholders/test values such as `example`, `changeme`, `dummy`, `placeholder`,
`test-secret`, and `not-a-real-secret` are suppressed.

Additional test values can be allow-listed by supplying their already-computed HMAC hash
in `allowlisted_hashes`. Raw allow-list secrets should not be persisted.

## Attack-path signal

If the same secret evidence hash appears on different assets, V13 creates a
`credential_reuse_across_assets` attack-path signal. The signal contains asset IDs,
a safe rationale and confidence, never the credential itself.

## API

POST `/api/v1/secret-exposure/imports`

GET `/api/v1/secret-exposure/imports`

GET `/api/v1/secret-exposure/imports/{import_id}/findings`

GET `/api/v1/secret-exposure/attack-path-signals`

## Deterministic example

```json
{
  "asset_id": null,
  "source_type": "configuration",
  "source_name": "lab.env",
  "payload": {
    "location": "lab.env",
    "text": "JWT_SECRET=REPLACE_WITH_A_TEST_VALUE"
  },
  "allowlisted_hashes": []
}
```

For realistic validation, use a fabricated non-production value that does not match the
built-in placeholder suppression terms. Do not test with real credentials.

## Gitleaks import

V13 imports Gitleaks JSON evidence. The parser consumes the scanner-reported secret only
long enough to produce a masked fingerprint/HMAC. It is not written to the database.

## Migration

```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1
alembic upgrade head
alembic current
```

Expected:

`0013_secret_exposure_assessment (head)`

## Tests

```powershell
pytest -v tests/test_secret_safety.py
pytest -v tests/test_secret_patterns.py
pytest -v tests/test_gitleaks_parser.py
pytest -v tests/test_secret_no_raw_output.py
pytest -v tests/test_secret_reporting.py
pytest -v
```

## Run

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected version: `0.13.0`

Expected API group: `secret-exposure-assessment`
