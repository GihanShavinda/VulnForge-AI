from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ExposureCandidate:
    rule_code: str
    title: str
    category: str
    severity: str
    conclusion: str
    evidence: dict[str, object]


RISKY_PORTS: dict[tuple[int, str], str] = {
    (21, "tcp"): "FTP",
    (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet",
    (80, "tcp"): "HTTP",
    (88, "tcp"): "Kerberos",
    (88, "udp"): "Kerberos",
    (111, "tcp"): "RPC",
    (111, "udp"): "RPC",
    (135, "tcp"): "RPC",
    (161, "udp"): "SNMP",
    (389, "tcp"): "LDAP",
    (443, "tcp"): "HTTPS",
    (445, "tcp"): "SMB",
    (3306, "tcp"): "MySQL",
    (3389, "tcp"): "RDP",
    (5432, "tcp"): "PostgreSQL",
    (5900, "tcp"): "VNC",
    (5985, "tcp"): "WinRM",
    (5986, "tcp"): "WinRM HTTPS",
    (6379, "tcp"): "Redis",
    (27017, "tcp"): "MongoDB",
}

DATABASE_PORTS = {
    (3306, "tcp"): "MySQL",
    (5432, "tcp"): "PostgreSQL",
    (6379, "tcp"): "Redis",
    (27017, "tcp"): "MongoDB",
}

ADMIN_SERVICE_NAMES = {"ssh", "telnet", "ms-wbt-server", "rdp", "vnc", "winrm", "wsman"}


def _script_text(scripts: Mapping[str, str]) -> str:
    return "\n".join(scripts.values()).lower()


def evaluate_exposure_rules(
    *,
    port: int,
    protocol: str,
    state: str,
    service: str | None,
    product: str | None,
    version: str | None,
    banner: str | None,
    tls_indicator: bool,
    scripts: Mapping[str, str],
    asset_role: str | None,
) -> list[ExposureCandidate]:
    # Exposure rules apply only to confirmed open services. An exposure finding
    # is not a vulnerability verdict; it records security-relevant attack surface.
    if state != "open":
        return []

    svc = (service or "").lower()
    role = (asset_role or "").lower()
    evidence = {
        "port": port,
        "protocol": protocol,
        "state": state,
        "service": service,
        "product": product,
        "version": version,
        "banner": banner,
        "tls_indicator": tls_indicator,
        "scripts": dict(scripts),
    }
    findings: list[ExposureCandidate] = []

    risky_name = RISKY_PORTS.get((port, protocol))
    if risky_name:
        findings.append(ExposureCandidate(
            rule_code="RISKY_SERVICE_EXPOSED",
            title=f"{risky_name} service exposed",
            category="attack_surface",
            severity="info",
            conclusion=(
                f"{risky_name} is reachable on {protocol.upper()}/{port}. "
                "This is an exposure observation, not a vulnerability determination."
            ),
            evidence=evidence,
        ))

    if port == 23 or svc == "telnet":
        findings.append(ExposureCandidate(
            "TELNET_ENABLED", "Telnet enabled", "unencrypted_service", "high",
            "Telnet is reachable and normally transmits session data without transport encryption.", evidence
        ))

    ftp_text = _script_text(scripts)
    if (port == 21 or svc == "ftp") and (
        "anonymous ftp login allowed" in ftp_text or "anonymous login allowed" in ftp_text
    ):
        findings.append(ExposureCandidate(
            "FTP_ANONYMOUS_INDICATOR", "FTP anonymous-access indicator", "access_exposure", "medium",
            "Nmap NSE evidence indicates that anonymous FTP login is allowed.", evidence
        ))

    smb_text = _script_text(scripts)
    if (port == 445 or svc in {"microsoft-ds", "netbios-ssn"}) and (
        "smbv1" in smb_text or "nt lm 0.12" in smb_text
    ):
        findings.append(ExposureCandidate(
            "SMBV1_INDICATOR", "SMBv1 indicator", "legacy_protocol", "high",
            "Nmap protocol evidence contains an SMBv1 indicator. This finding records protocol exposure only.", evidence
        ))

    if port == 3389 or svc in {"ms-wbt-server", "rdp"}:
        findings.append(ExposureCandidate(
            "RDP_EXPOSED", "RDP exposed", "administrative_service", "medium",
            "Remote Desktop service is reachable from the scanner inside the approved lab scope.", evidence
        ))

    db_name = DATABASE_PORTS.get((port, protocol))
    if db_name:
        findings.append(ExposureCandidate(
            "DATABASE_EXPOSED", f"{db_name} database service exposed", "database_exposure", "medium",
            f"{db_name} is reachable on {protocol.upper()}/{port}. Reachability alone does not imply a vulnerability.", evidence
        ))

    if port in {23, 5985} or svc in {"telnet", "wsman"} and not tls_indicator:
        findings.append(ExposureCandidate(
            "UNENCRYPTED_MANAGEMENT_SERVICE", "Unencrypted management service", "unencrypted_service", "medium",
            "A management-oriented service is reachable without a TLS indicator in the Nmap evidence.", evidence
        ))

    if port in {21, 23} or svc in {"ftp", "telnet"}:
        findings.append(ExposureCandidate(
            "LEGACY_SERVICE", "Legacy service exposed", "legacy_service", "medium",
            "A legacy clear-text service is reachable and should be reviewed for business need and compensating controls.", evidence
        ))

    administrative = port in {22, 23, 3389, 5900, 5985, 5986} or svc in ADMIN_SERVICE_NAMES
    expected_role_tokens = {"server", "admin", "management", "security-testing"}
    if administrative and role and not any(token in role for token in expected_role_tokens):
        findings.append(ExposureCandidate(
            "UNEXPECTED_ADMIN_SERVICE", "Unexpected administrative service", "administrative_service", "medium",
            f"An administrative service is exposed on an asset whose recorded role is '{asset_role}'. Review whether it is expected.",
            evidence,
        ))

    return findings
