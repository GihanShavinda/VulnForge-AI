from __future__ import annotations

from dataclasses import dataclass

import winrm


class WinRMAuthenticationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CollectedItem:
    category: str
    locator: str
    value: str


WINDOWS_COMMANDS: tuple[tuple[str, str], ...] = (
    ("windows_os_version", "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | Format-List | Out-String"),
    ("installed_software", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 300"),
    ("hotfixes", "Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String -Width 300"),
    ("services", "Get-Service | Select-Object Name,DisplayName,Status,StartType | Sort-Object Name | Format-Table -AutoSize | Out-String -Width 300"),
    ("local_users_groups", "cmd /c 'net user'; cmd /c 'net localgroup'"),
    ("firewall_state", "cmd /c 'netsh advfirewall show allprofiles'"),
    ("smb_configuration", "if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,EncryptData,RequireSecuritySignature | Format-List | Out-String } else { cmd /c 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB1'; cmd /c 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB2' }"),
    ("rdp_configuration", "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue | Select-Object fDenyTSConnections | Format-List | Out-String"),
    ("defender_status", "if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List | Out-String } else { 'Defender cmdlets unavailable on this system.' }"),
    ("powershell_version", "$PSVersionTable | Format-List | Out-String"),
    ("local_security_policy", "$p=Join-Path $env:TEMP 'vulnforge-secpol.cfg'; secedit /export /cfg $p /quiet 2>$null; if(Test-Path $p){Get-Content $p; Remove-Item $p -Force}"),
    ("listening_ports", "cmd /c 'netstat -ano | findstr LISTENING'"),
    ("installed_updates", "Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID,Description,InstalledOn | Format-Table -AutoSize | Out-String -Width 300"),
)


def collect_windows_winrm(host: str, username: str, password: str, port: int = 5985, timeout: int = 20) -> list[CollectedItem]:
    endpoint = f"http://{host}:{port}/wsman"
    session = winrm.Session(endpoint, auth=(username, password), transport="ntlm")

    # One authentication probe only. A failed probe aborts immediately to reduce
    # account-lockout risk.
    probe = session.run_ps("$PSVersionTable.PSVersion.ToString()")
    if probe.status_code in {401, 403}:  # pywinrm surfaces HTTP auth failures here
        raise WinRMAuthenticationError("WinRM authentication failed. No retry was attempted.")
    if probe.status_code != 0:
        raise RuntimeError((probe.std_err or b"WinRM probe failed").decode("utf-8", errors="replace"))

    results: list[CollectedItem] = []
    for category, command in WINDOWS_COMMANDS:
        response = session.run_ps(command)
        stdout = response.std_out.decode("utf-8", errors="replace")
        stderr = response.std_err.decode("utf-8", errors="replace")
        combined = stdout if not stderr.strip() else f"{stdout}\n[stderr]\n{stderr}"
        results.append(CollectedItem(category, command, combined.strip()))
    return results
