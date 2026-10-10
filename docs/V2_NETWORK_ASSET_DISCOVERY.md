# V2 — Network Asset Discovery

## Security goal

V2 answers the first operational question in the VulnForge workflow: **which systems are actually present and reachable inside the authorized environment?**

Nmap is the primary discovery engine, but VulnForge remains the security control plane. Nmap never receives a target until the complete IP or CIDR is proven to be contained within an enabled `ScanScope` belonging to a network marked `approved_for_scanning=true`.

## Discovery methods

### ICMP

Uses Nmap host discovery with common ICMP echo/timestamp/address-mask probes where supported. Firewalls can block ICMP, so absence of a response does not prove a system is offline.

### ARP

Uses ARP discovery (`-PR`). This is normally the most reliable choice for systems on the same VMware Host-Only Ethernet segment because ARP is necessary for local IPv4 communication. It does not work as a routed remote-network discovery method.

### TCP

Uses TCP SYN probes on common ports plus ACK probes. This can discover hosts that ignore ICMP but respond to TCP. A host can still be missed if its firewall silently drops the selected probes.

## XML evidence

V2 never parses Nmap's human-readable terminal output.

Nmap writes XML using `-oX`. VulnForge stores the raw XML exactly as captured in `DiscoveryEvidence`, calculates a SHA-256 digest, then parses normalized host facts from that evidence.

Evidence is committed before normalization so parser/reconciliation failures do not erase the scanner output.

## Entities

### DiscoveryJob

Tracks:
- requested target
- method
- source (`nmap`)
- status
- exact argument list
- authorization flag
- start/completion times
- errors

### DiscoveredHost

Stores one observation with:
- IP address
- hostname
- MAC address
- vendor
- reachable/state
- first seen
- last seen
- scan source
- scan timestamp
- matched manual Asset ID
- identity basis
- detected changes

### DiscoveryEvidence

Stores:
- job ID
- evidence type
- raw Nmap XML
- SHA-256
- capture timestamp

## Reconciliation

V2 does not automatically create a permanent/manual Asset for every unknown observation. That avoids inventory pollution caused by temporary devices or ambiguous results.

Observed hosts are reconciled against existing manual Assets using the strongest available evidence:

1. existing manual Asset identity once linked/preserved by `matched_asset_id`
2. MAC address
3. unique hostname
4. IP address

The matched manual Asset ID becomes the stable identity reference for the observation.

## Change detection

V2 records the following signals:

- `new_asset`: no existing Asset can be reconciled
- `missing_asset`: a manual Asset in the scanned range was not observed
- `ip_change`: stable identity (normally MAC) is observed at a different IP
- `hostname_change`: stable identity is observed with a different hostname
- `mac_change`: host reconciled by hostname/IP now exposes a different MAC
- `newly_reachable`: an Asset previously marked unreachable responds again

A missing observation does **not** delete an Asset. It sets the inventory reachability state to false and preserves history.

## Scope safety

For CIDR discovery, checking only one address is unsafe. V2 therefore requires the **entire requested network** to be a subnet of one approved scope.

Example:

- Approved scope: `192.168.56.0/24`
- Allowed: `192.168.56.0/24`
- Allowed: `192.168.56.0/25`
- Allowed: `192.168.56.20`
- Denied: `192.168.0.0/16`
- Denied: `8.8.8.8`

## False positives

Host discovery can produce misleading identity/change signals when:

- DHCP reuses an old IP for a different machine
- virtual NICs are regenerated and MAC addresses change
- cloned VMs share or duplicate hostnames
- DNS/PTR records are stale
- NAT/proxy devices obscure the actual endpoint
- multiple interfaces belong to one logical machine

VulnForge therefore records the identity basis and evidence instead of pretending reconciliation is certain.

## False negatives

A system can be present but not discovered because:

- ICMP is blocked
- selected TCP probes are silently dropped
- the VM is sleeping/paused
- host firewall policy rejects probes
- ARP is attempted across a routed boundary
- packet loss occurs
- a temporary network fault exists
- Nmap lacks privileges for a probe type

Therefore `missing_asset` means **not observed in this discovery run**, not proven absent from the environment.

## Verification workflow

1. Confirm V1 approved Network and ScanScope exist.
2. Confirm Nmap is installed.
3. Apply migration `0002_network_asset_discovery`.
4. Run tests.
5. Start backend and frontend.
6. Run ARP discovery against the VMware Host-Only CIDR.
7. Confirm known VMs appear with IP/MAC/vendor where available.
8. Open raw XML evidence for the job.
9. Repeat after changing one VM state or identity and confirm change signals.
10. Attempt an out-of-scope CIDR and confirm HTTP 403 before Nmap executes.

## Common errors

### Nmap executable was not found on PATH

Install Nmap and reopen PowerShell. Verify `Get-Command nmap`.

### Discovery returns HTTP 403

Confirm:
- Network is approved for scanning
- ScanScope is enabled
- requested target is completely inside that scope
- explicit authorization is checked

### No MAC/vendor values

MAC/vendor data is normally available only on the local L2 segment and depends on Nmap/OUI data. Routed discovery often has no endpoint MAC.

### Hostnames are blank

PTR/DNS data may not exist. A blank hostname is valid evidence; VulnForge does not invent one.

### A live host is marked missing

Try ARP discovery on the local Host-Only network or TCP discovery if ICMP is filtered. Review raw XML before changing inventory.
