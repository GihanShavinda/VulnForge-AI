# VulnForge AI 2.0 — V3 Service & Attack-Surface Enumeration

V3 takes manually managed, scope-approved Assets from V1/V2 and performs evidence-backed Nmap service enumeration. It does not exploit services and it does not label an open port as a vulnerability.

## Captured service evidence
- TCP or UDP port
- protocol
- state
- service name
- product
- version
- banner when Nmap/NSE supplies one
- CPE
- TLS indicator
- Nmap service confidence (0–10)
- detection source
- raw Nmap XML + SHA-256

## Exposure rules
Rules are conclusions over scanner evidence. Examples include Telnet enabled, FTP anonymous-access indicator, SMBv1 indicator, RDP exposed, database exposed, unencrypted management service, legacy service, and unexpected administrative service. `RISKY_SERVICE_EXPOSED` is informational and explicitly does not mean the service is vulnerable.

## Change detection
Compared against the most recent completed enumeration job for the same Asset and transport protocol:
- new_port
- closed_port
- service_changed
- version_changed
- protocol_changed

A synthetic `closed` observation is created when a previously-open endpoint is absent from the next completed scan of the same protocol. This is a scan-diff conclusion and should be interpreted with Nmap reachability/scan-quality limitations in mind.

## Safety
- Enumeration only runs for an existing Asset with `scanning_enabled=true`.
- The Asset IP must pass the same approved ScanScope validation used by V2.
- Explicit authorization is honored.
- No automatic exploitation is implemented.
- Raw XML is preserved before parsing/rule evaluation.
