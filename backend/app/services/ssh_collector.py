from __future__ import annotations

from dataclasses import dataclass

import paramiko


class SSHAuthenticationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CollectedItem:
    category: str
    locator: str
    value: str


LINUX_COMMANDS: tuple[tuple[str, str], ...] = (
    ("os_release", "cat /etc/os-release 2>/dev/null || true"),
    ("kernel", "uname -a; uname -r"),
    ("installed_packages", "(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null || rpm -qa 2>/dev/null || true)"),
    ("running_services", "(systemctl list-units --type=service --state=running --no-pager 2>/dev/null || service --status-all 2>/dev/null || true)"),
    ("users_groups", "getent passwd; echo '---GROUPS---'; getent group"),
    ("sudo_indicators", "sudo -n -l 2>&1 || true; grep -R -nE '^[^#].*(ALL|NOPASSWD)' /etc/sudoers /etc/sudoers.d 2>/dev/null || true"),
    ("listening_sockets", "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true"),
    ("patch_information", "(apt list --upgradable 2>/dev/null || dnf check-update 2>/dev/null || yum check-update 2>/dev/null || true)"),
    ("firewall_status", "(ufw status verbose 2>/dev/null || firewall-cmd --state 2>/dev/null || iptables -S 2>/dev/null || true)"),
    ("ssh_configuration", "(sshd -T 2>/dev/null || grep -E '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups|Protocol)' /etc/ssh/sshd_config 2>/dev/null || true)"),
    ("scheduled_jobs", "crontab -l 2>/dev/null || true; find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f -printf '%p\n' 2>/dev/null || true"),
    ("important_file_permissions", "stat -c '%A %a %U:%G %n' /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/ssh/sshd_config 2>/dev/null || true"),
)


def collect_linux_ssh(host: str, username: str, password: str, port: int = 22, timeout: int = 10) -> list[CollectedItem]:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=username, password=password,
            timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
            allow_agent=False, look_for_keys=False,
        )
    except paramiko.AuthenticationException as exc:
        raise SSHAuthenticationError("SSH authentication failed. No retry was attempted.") from exc
    except paramiko.SSHException as exc:
        raise RuntimeError(f"SSH trust/transport failure: {exc}. Add the approved lab host key to the scanner account known_hosts before retrying.") from exc
    except Exception as exc:
        raise RuntimeError(f"SSH connection failed: {exc}") from exc

    results: list[CollectedItem] = []
    try:
        for category, command in LINUX_COMMANDS:
            stdin, stdout, stderr = client.exec_command(command, timeout=30)
            _ = stdin
            text = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            combined = text if not err.strip() else f"{text}\n[stderr]\n{err}"
            results.append(CollectedItem(category, command, combined.strip()))
    finally:
        client.close()
    return results
