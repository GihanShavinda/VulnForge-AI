# VulnForge AI 2.0 — V5 Credentialed Assessment

V5 adds credentialed, read-only assessment for explicitly authorized lab systems.

## Safety properties
- Every remote target still passes the existing approved-scope validator.
- SSH is used for Linux.
- WinRM/PowerShell is used only for non-legacy Windows systems.
- Windows XP/Windows 7 should use imported authenticated evidence rather than insecure remote automation.
- No plaintext password is stored. Secrets are encrypted with Fernet using `VULNFORGE_CREDENTIAL_KEY`.
- Secrets are never returned by API responses or written to audit records.
- One failed remote authentication attempt increments the profile failure counter; the collector does not retry the password.
- Reaching `max_failed_attempts` creates a 15-minute local VulnForge lockout.

## Generate the encryption key
```powershell
cd "F:\My_Projects\Vulnforge\backend"
.\.venv\Scripts\Activate.ps1
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Add the generated value to `backend/.env`:
```text
VULNFORGE_CREDENTIAL_KEY=PASTE_GENERATED_KEY_HERE
```
Never commit this key. Keep a secure backup; changing it makes existing encrypted secrets unreadable.

## Install V5 dependencies
```powershell
pip install -r requirements.txt
```

## Migrate
```powershell
alembic upgrade head
alembic current
```
Expected: `0005_authenticated_assessment (head)`

## SSH host-key trust
V5 uses strict SSH host-key verification. Add each approved Linux VM key to the scanner account's `known_hosts` before the first scan. With Windows OpenSSH tools installed:
```powershell
New-Item -ItemType Directory -Force "$HOME\.ssh" | Out-Null
ssh-keyscan 192.168.37.20 | Add-Content "$HOME\.ssh\known_hosts"
```
Verify the fingerprint from the VM console before trusting it.

## Linux flow
1. Create an SSH credential with `POST /api/v1/authenticated/credentials`.
2. Run `POST /api/v1/authenticated/scans`.
3. V5 collects OS release, kernel, packages, services, users/groups, sudo indicators, sockets, patch data, firewall, SSH settings, cron jobs and important file permissions.

## Legacy Windows flow
Do not enable insecure WinRM solely for V5. For Windows 7/XP, collect trusted local evidence and submit it to `POST /api/v1/authenticated/scans/import`.

## Comparison
`GET /api/v1/authenticated/scans/{scan_id}/comparison` shows where authenticated evidence raises confidence and where local listening sockets differ from unauthenticated network observations.
