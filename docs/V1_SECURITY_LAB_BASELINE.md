# V1 — Security Lab & Network Baseline

## 1. Security goal

V1 creates the safety boundary that every future VulnForge scanning feature must obey.

The most important rule is:

> No scan command may be launched until the destination has passed central scope validation.

This prevents accidental assessment of systems outside the authorised VMware laboratory.

## 2. VMware network architecture

Use a dedicated VMware **Host-Only** network for the security lab.

Recommended example:

- Network: `192.168.56.0/24`
- Scanner host: `192.168.56.10`
- Kali: `192.168.56.11`
- Metasploitable2: `192.168.56.20`
- OWASP vulnerable target: `192.168.56.21`
- Windows XP: `192.168.56.30`
- Windows 7: `192.168.56.31`
- Windows 10: `192.168.56.32`
- Ubuntu Desktop: `192.168.56.40`
- Ubuntu CLI: `192.168.56.41`

Adapt these values to your actual VMware VMnet configuration.

### Optional NAT network

A second NAT adapter may be enabled temporarily for patching or controlled package
updates, but intentionally vulnerable machines should not remain connected to that
network.

Preferred workflow:

1. Shut down the VM.
2. Take a snapshot.
3. Attach the controlled NAT adapter.
4. Perform required updates.
5. Shut down the VM again.
6. Remove or disable the NAT adapter.
7. Return to Host-Only mode.
8. Confirm the VM's Host-Only address.
9. Resume assessment.

## 3. Static addressing

Static addresses make evidence repeatable.

Do not rely on changing DHCP addresses for intentionally vulnerable systems because
a changed IP could cause evidence, findings or future attack-graph nodes to refer to
the wrong machine.

Maintain a single authoritative IP plan in VulnForge.

## 4. Core V1 entities

### Network

Represents an isolated network segment and whether it is approved for scanning.

Important fields:

- name
- CIDR
- network type
- approved-for-scanning flag
- description

### Asset

Represents one lab system.

Important fields:

- network
- hostname
- IP address
- operating system
- role
- vulnerable-target flag
- scanning-enabled flag

### ScanScope

Defines the exact CIDR that a scanner is allowed to assess.

A scope can also enforce:

- explicit authorization
- enabled/disabled state
- maintenance window
- timezone

### AssetTag

Adds security context such as:

- legacy-os
- web-target
- linux
- windows
- intentionally-vulnerable
- crown-jewel
- scanner-host

### CredentialProfile

Stores metadata about an authenticated-scanning credential.

V1 does **not** store plaintext secrets.

The `secret_reference` field should reference a secure local secret location,
Windows Credential Manager entry, password-vault key, environment-variable key or
another secret-management mechanism.

### ScanProfile

Stores conservative scan limits:

- scanner type
- timeout
- maximum concurrency
- evidence-retention period
- scope-validation requirement
- authorization requirement

### AuditLog

Records safety-relevant decisions.

V1 records scope-validation outcomes so later reviews can establish:

- what target was requested
- whether it was allowed
- why it was allowed or denied
- which scope matched

## 5. Scope validation policy

The V1 validator accepts **literal IP addresses only**.

This is deliberate.

Allowing arbitrary hostnames during V1 could introduce DNS-based ambiguity where a
name resolves to an address outside the approved laboratory.

Hostname support can be introduced later through a controlled resolver that:

1. resolves the hostname,
2. records the resolved IP evidence,
3. validates every resolved address,
4. rejects mixed in-scope/out-of-scope results,
5. prevents DNS rebinding between validation and execution.

### Automatically blocked targets

The V1 validator blocks:

- malformed addresses
- loopback/localhost
- multicast
- unspecified addresses
- link-local addresses
- reserved addresses
- IPv4 subnet identifiers
- IPv4 directed broadcast addresses
- any address outside all enabled approved scopes
- an in-scope target without required explicit authorization
- a target outside its maintenance window

## 6. Scan authorization model

Recommended V1 flow:

1. User selects a known Asset or enters a literal lab IP.
2. Backend loads only enabled scopes attached to networks marked
   `approved_for_scanning=true`.
3. Backend validates the target.
4. Backend checks explicit authorization.
5. Backend checks maintenance-window rules.
6. Backend writes an audit event.
7. Only an `allowed=true` decision may be handed to a future scanner adapter.

Future scanner services must never duplicate or bypass this policy.

## 7. Timeout limits

Use conservative scan timeouts.

Recommended V1 default:

- 900 seconds per scan operation

Later milestones may define scanner-specific limits, but all limits should have hard
upper bounds.

A timeout should terminate the scanner subprocess and mark the job incomplete rather
than allowing an orphan process to continue indefinitely.

## 8. Concurrency limits

Recommended V1 default:

- 2 concurrent scan jobs

The goal is to protect:

- old Windows targets
- Metasploitable2
- local VMware networking
- the scanner host
- evidence quality

Aggressive concurrency may create packet loss, false negatives or VM instability.

## 9. Maintenance windows

Some targets should only be scanned during planned laboratory sessions.

A `ScanScope` can define start/end times and a timezone.

Overnight windows are supported, for example:

- 22:00 -> 02:00

If no start/end time is configured, the scope is considered continuously available.

## 10. Evidence retention

V1 stores the desired evidence-retention period on the scan profile even though
evidence ingestion is implemented in later milestones.

Recommended development default:

- 90 days

Retention should eventually account for:

- disk usage
- research reproducibility
- remediation verification
- privacy
- credential leakage risk
- report traceability

## 11. Snapshots

Take VMware snapshots before:

- changing target network settings
- enabling vulnerable services
- installing intentionally vulnerable software
- running destructive administrative tests
- making security-hardening changes that will later be verified

Use meaningful names such as:

`win7-before-hardening-2026-10-07`

## 12. Isolation

Intentionally vulnerable systems must remain isolated from untrusted networks.

Especially protect:

- Windows XP
- Windows 7
- Metasploitable2
- deliberately vulnerable OWASP applications

Do not use bridged networking for these systems.

## 13. Restoring vulnerable machines

After a lab exercise:

1. Stop active scanners.
2. Preserve required evidence.
3. Shut down the target if necessary.
4. Revert to a known VMware snapshot.
5. Confirm Host-Only networking.
6. Confirm the static IP.
7. Confirm the asset still matches VulnForge inventory.
8. Only then resume future assessments.

## 14. Least privilege

Run the FastAPI backend and scanner orchestration under a normal operating-system
account.

Only elevate privileges for a narrowly defined scanner operation that truly requires
them.

Do not run the whole VulnForge application as Administrator.

## 15. Credential storage policy

Never commit passwords, SSH private keys, API tokens or domain credentials to Git.

V1 stores a **secret reference**, not the secret itself.

Recommended options:

- Windows Credential Manager
- environment variables
- local password manager
- protected secrets file outside the repository

Future authenticated scanners should request a secret only at execution time and
avoid persisting it into evidence or logs.

## 16. Tests required before V2

Confirm tests cover:

- valid host in scope
- explicit authorization required
- host outside scope
- malformed address
- localhost
- multicast
- IPv4 subnet identifier
- IPv4 broadcast
- IPv6 link-local
- IPv6 multicast
- IPv6 unspecified address
- valid IPv6 ULA host
- disabled scope
- maintenance-window denial
- overnight maintenance-window success

## 17. Common errors and fixes

### PostgreSQL connection refused

Verify:

- PostgreSQL service is running
- `DATABASE_URL` uses the correct host and port
- the database exists
- the role has access

### Alembic cannot find app modules

Run Alembic from the `backend` directory with the virtual environment activated.

### A valid lab IP is denied

Check:

- the Network is `approved_for_scanning`
- the ScanScope is enabled
- the CIDR is correct
- explicit authorization is true
- the current time is inside the maintenance window

### Broadcast address is rejected

This is expected.

For `192.168.56.0/24`:

- `192.168.56.0` is the network address
- `192.168.56.255` is the directed broadcast address

Neither should be a scan target.

### Hostname is rejected

This is expected in V1.

Use the target's literal Host-Only IP address. Controlled hostname resolution should
be added only when it preserves the same safety guarantees.

## 18. V1 security coverage improvement

Before V1, later scan integrations would have no single enforceable boundary.

After V1, VulnForge has:

- an explicit lab inventory
- an approved network model
- a scope allow-list
- scan authorization
- hard target exclusions
- maintenance windows
- scan limits
- auditability
- safe credential metadata
- documented VMware isolation practices

This makes V1 the security control plane for every later discovery and assessment
milestone.
