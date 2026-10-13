from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleResult:
    control: str
    expected_state: str
    observed_state: str
    evidence: dict
    severity: str
    remediation: str
    confidence: str
    framework_reference: list[str]


def _boolish(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"true", "yes", "enabled", "on", "1"}:
        return True
    if normalized in {"false", "no", "disabled", "off", "0"}:
        return False
    return None


def _finding(control, expected, observed, evidence, severity, remediation, confidence, refs):
    return RuleResult(control, expected, observed, evidence, severity, remediation, confidence, refs)


def evaluate_control(control_id: str, observed_value: str, raw: dict, confidence: str) -> RuleResult | None:
    v = observed_value.strip()
    lower = v.lower()

    if control_id == "linux.root_ssh_login":
        insecure = lower in {"yes", "permitrootlogin yes", "enabled", "true"}
        if insecure:
            return _finding(
                "Disable direct root SSH login",
                "PermitRootLogin should be disabled or restricted.",
                v,
                raw,
                "High",
                "Set PermitRootLogin no (or an explicitly justified restricted mode), then reload SSH safely.",
                confidence,
                ["CIS concept: restrict direct root remote login"],
            )

    elif control_id == "linux.password_authentication":
        if _boolish(v) is True or lower == "passwordauthentication yes":
            return _finding(
                "Disable SSH password authentication where feasible",
                "Prefer key-based SSH authentication for managed servers.",
                v,
                raw,
                "Medium",
                "Use public-key authentication and disable PasswordAuthentication after validating access.",
                confidence,
                ["CIS concept: harden SSH authentication"],
            )

    elif control_id == "linux.firewall_enabled":
        if _boolish(v) is False:
            return _finding(
                "Host firewall enabled",
                "A host firewall should be enabled with an explicit policy.",
                v,
                raw,
                "High",
                "Enable and configure the approved host firewall before exposing services.",
                confidence,
                ["CIS concept: host-based firewall"],
            )

    elif control_id == "linux.weak_file_permissions":
        if any(token in lower for token in ["777", "666", "world-writable", "group/world writable"]):
            return _finding(
                "Restrict sensitive file permissions",
                "Sensitive files should not grant unnecessary write access.",
                v,
                raw,
                "High",
                "Reduce permissions and ownership to the minimum required by the service.",
                confidence,
                ["CIS concept: filesystem permissions"],
            )

    elif control_id == "linux.insecure_sudo":
        if any(token in lower for token in ["nopasswd: all", "all=(all) nopasswd: all", "all=(all:all) all"]):
            return _finding(
                "Restrict sudo privileges",
                "Sudo rights should be narrowly scoped and attributable.",
                v,
                raw,
                "High",
                "Replace broad sudo grants with command-specific least-privilege rules and validate using visudo.",
                confidence,
                ["CIS concept: least privilege for sudo"],
            )

    elif control_id == "linux.world_writable_files":
        if lower not in {"none", "0", "[]"}:
            return _finding(
                "Remove unnecessary world-writable files",
                "World-writable files should be absent unless explicitly required.",
                v,
                raw,
                "Medium",
                "Review each path and remove world-write permission where not operationally required.",
                confidence,
                ["CIS concept: filesystem integrity and permissions"],
            )

    elif control_id == "linux.legacy_protocols":
        if any(token in lower for token in ["telnet", "rsh", "rlogin", "rexec", "ftp"]):
            return _finding(
                "Disable legacy clear-text protocols",
                "Legacy clear-text administration protocols should not be enabled.",
                v,
                raw,
                "High",
                "Remove or disable legacy services and use encrypted replacements such as SSH/SFTP.",
                confidence,
                ["CIS concept: minimize insecure network services"],
            )

    elif control_id == "linux.weak_ssh_algorithms":
        if any(token in lower for token in ["ssh-rsa", "diffie-hellman-group1-sha1", "3des-cbc", "aes128-cbc", "hmac-sha1"]):
            return _finding(
                "Remove weak SSH algorithms",
                "Only organization-approved modern SSH algorithms should be enabled.",
                v,
                raw,
                "Medium",
                "Remove deprecated ciphers, MACs and key-exchange algorithms after compatibility testing.",
                confidence,
                ["CIS concept: SSH cryptographic hardening"],
            )

    elif control_id == "linux.unsafe_anonymous_services":
        if any(token in lower for token in ["anonymous ftp enabled", "anonymous=true", "anonymous enabled"]):
            return _finding(
                "Disable unsafe anonymous services",
                "Anonymous access should be disabled unless explicitly required and isolated.",
                v,
                raw,
                "High",
                "Disable anonymous authentication or restrict it to an approved isolated service.",
                confidence,
                ["CIS concept: restrict unauthenticated network access"],
            )

    elif control_id == "linux.unnecessary_services":
        if lower not in {"none", "[]", "0"}:
            return _finding(
                "Disable unnecessary services",
                "Only services required for the host role should run.",
                v,
                raw,
                "Medium",
                "Review listed services against the asset role and disable those not required.",
                confidence,
                ["CIS concept: minimize attack surface"],
            )

    elif control_id == "linux.unnecessary_listening_ports":
        if lower not in {"none", "[]", "0"}:
            return _finding(
                "Close unnecessary listening ports",
                "Only ports required for the approved host role should listen.",
                v,
                raw,
                "Medium",
                "Identify the owning service and close or firewall ports not required for the asset role.",
                confidence,
                ["CIS concept: minimize exposed services"],
            )

    elif control_id == "windows.guest_account":
        if _boolish(v) is True or "enabled" in lower:
            return _finding(
                "Disable Guest account",
                "Guest account should be disabled.",
                v,
                raw,
                "High",
                "Disable the built-in Guest account unless an approved exception exists.",
                confidence,
                ["CIS concept: disable Guest account"],
            )

    elif control_id == "windows.smbv1":
        if _boolish(v) is True or "smbv1 enabled" in lower:
            return _finding(
                "Disable SMBv1",
                "SMBv1 should be disabled.",
                v,
                raw,
                "Critical",
                "Disable SMBv1 and validate application compatibility with SMBv2/SMBv3.",
                confidence,
                ["CIS concept: disable legacy SMB"],
            )

    elif control_id == "windows.firewall_enabled":
        if _boolish(v) is False or "disabled" in lower:
            return _finding(
                "Windows Firewall enabled",
                "Firewall profiles should be enabled with an approved ruleset.",
                v,
                raw,
                "High",
                "Enable required Windows Firewall profiles and review inbound rules.",
                confidence,
                ["CIS concept: host firewall"],
            )

    elif control_id == "windows.rdp_configuration":
        if any(token in lower for token in ["nla disabled", "securitylayer 0", "allowtsconnections=1 without nla"]):
            return _finding(
                "Harden Remote Desktop",
                "RDP should use Network Level Authentication and approved access controls.",
                v,
                raw,
                "High",
                "Require NLA, restrict RDP exposure, and limit access to approved administrators.",
                confidence,
                ["CIS concept: secure Remote Desktop Services"],
            )

    elif control_id == "windows.unnecessary_services":
        if lower not in {"none", "[]", "0"}:
            return _finding(
                "Disable unnecessary Windows services",
                "Only services required for the workstation/server role should run.",
                v,
                raw,
                "Medium",
                "Review service dependencies and disable unneeded services using approved change control.",
                confidence,
                ["CIS concept: minimize attack surface"],
            )

    elif control_id == "windows.local_admin_exposure":
        if any(token in lower for token in ["multiple interactive admins", "domain users", "everyone", "excessive"]):
            return _finding(
                "Restrict local administrator membership",
                "Local Administrators should contain only approved administrative principals.",
                v,
                raw,
                "High",
                "Remove unnecessary principals and manage local admin rights through controlled policy.",
                confidence,
                ["CIS concept: least privilege for local administrators"],
            )

    elif control_id == "windows.password_policy":
        if any(token in lower for token in ["minimum length 0", "complexity disabled", "lockout threshold 0"]):
            return _finding(
                "Strengthen local password policy",
                "Password and lockout policy should meet the organization's baseline.",
                v,
                raw,
                "Medium",
                "Apply an approved password/lockout baseline via local or domain policy.",
                confidence,
                ["CIS concept: account and password policy"],
            )

    elif control_id == "windows.legacy_os":
        if any(token in lower for token in ["windows 7", "windows server 2008", "windows xp", "end of support", "legacy"]):
            return _finding(
                "Remove unsupported legacy operating systems",
                "Operating systems should remain vendor-supported or be formally isolated by exception.",
                v,
                raw,
                "Critical",
                "Upgrade to a supported OS or isolate the system with compensating controls and a retirement plan.",
                confidence,
                ["CIS concept: supported and patched platform"],
            )

    elif control_id == "windows.security_protections":
        if any(token in lower for token in ["defender disabled", "antivirus disabled", "realtime disabled", "missing"]):
            return _finding(
                "Enable endpoint security protections",
                "Approved anti-malware and real-time protections should be enabled where supported.",
                v,
                raw,
                "High",
                "Enable the approved endpoint protection stack or document a compensating control.",
                confidence,
                ["CIS concept: malware defenses"],
            )

    elif control_id == "windows.anonymous_smb":
        if any(token in lower for token in ["null session enabled", "anonymous enabled", "restrictanonymous=0"]):
            return _finding(
                "Restrict anonymous SMB access",
                "Anonymous/null-session SMB access should be restricted.",
                v,
                raw,
                "High",
                "Restrict anonymous enumeration and unauthenticated SMB access using supported policy settings.",
                confidence,
                ["CIS concept: restrict anonymous access"],
            )

    elif control_id == "windows.remote_management":
        if any(token in lower for token in ["basic authentication enabled", "allowunencrypted=true", "unencrypted enabled"]):
            return _finding(
                "Harden remote management",
                "Remote management should require authenticated encrypted transport.",
                v,
                raw,
                "High",
                "Disable unencrypted transport/basic authentication and restrict WinRM to trusted administrative networks.",
                confidence,
                ["CIS concept: secure remote administration"],
            )

    return None
