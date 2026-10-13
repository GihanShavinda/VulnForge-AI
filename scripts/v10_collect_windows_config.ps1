param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\v10-windows-config-evidence.json"
)

$ErrorActionPreference = "SilentlyContinue"
$evidence = @()

function Add-Evidence {
    param(
        [string]$ControlId,
        [string]$Category,
        [string]$ObservedValue,
        [string]$SourceLocator
    )

    if ([string]::IsNullOrWhiteSpace($ObservedValue)) {
        return
    }

    $evidence += [PSCustomObject]@{
        control_id     = $ControlId
        category       = $Category
        observed_value = $ObservedValue
        source_locator = $SourceLocator
        confidence     = "confirmed"
    }
}

# Guest account
$guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
    Where-Object { $_.SID -match '-501$' } |
    Select-Object -First 1

if ($null -ne $guest) {
    Add-Evidence `
        -ControlId "windows.guest_account" `
        -Category "windows.account" `
        -ObservedValue ($(if ($guest.Disabled) { "disabled" } else { "enabled" })) `
        -SourceLocator "Win32_UserAccount SID-501"
}

# Windows Firewall
$profiles = Get-NetFirewallProfile
if ($profiles) {
    $allEnabled = ($profiles | Where-Object { -not $_.Enabled }).Count -eq 0
    Add-Evidence `
        -ControlId "windows.firewall_enabled" `
        -Category "windows.firewall" `
        -ObservedValue ($(if ($allEnabled) { "enabled" } else { "disabled" })) `
        -SourceLocator "Get-NetFirewallProfile"
}

# SMBv1
$smb = Get-SmbServerConfiguration
if ($null -ne $smb) {
    Add-Evidence `
        -ControlId "windows.smbv1" `
        -Category "windows.smb" `
        -ObservedValue ($(if ($smb.EnableSMB1Protocol) { "SMBv1 enabled" } else { "SMBv1 disabled" })) `
        -SourceLocator "Get-SmbServerConfiguration"
}

# RDP/NLA
$rdpPolicy = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
if ($null -ne $rdpPolicy) {
    $nla = $rdpPolicy.UserAuthentication
    Add-Evidence `
        -ControlId "windows.rdp_configuration" `
        -Category "windows.rdp" `
        -ObservedValue ($(if ($nla -eq 1) { "NLA enabled" } else { "NLA disabled" })) `
        -SourceLocator "RDP-Tcp\UserAuthentication"
}

# Local administrators
$admins = Get-LocalGroupMember -Group "Administrators" |
    Select-Object -ExpandProperty Name
if ($admins) {
    Add-Evidence `
        -ControlId "windows.local_admin_exposure" `
        -Category "windows.local_admins" `
        -ObservedValue ($admins -join ", ") `
        -SourceLocator "Get-LocalGroupMember Administrators"
}

# Password policy
$netAccounts = net accounts 2>$null | Out-String
if ($netAccounts) {
    Add-Evidence `
        -ControlId "windows.password_policy" `
        -Category "windows.password_policy" `
        -ObservedValue ($netAccounts.Trim()) `
        -SourceLocator "net accounts"
}

# OS version / legacy status indicator
$os = Get-CimInstance Win32_OperatingSystem
if ($null -ne $os) {
    Add-Evidence `
        -ControlId "windows.legacy_os" `
        -Category "windows.os" `
        -ObservedValue "$($os.Caption) $($os.Version)" `
        -SourceLocator "Win32_OperatingSystem"
}

# Defender status where available
$defender = Get-MpComputerStatus
if ($null -ne $defender) {
    $status = "AntivirusEnabled=$($defender.AntivirusEnabled); RealTimeProtectionEnabled=$($defender.RealTimeProtectionEnabled)"
    Add-Evidence `
        -ControlId "windows.security_protections" `
        -Category "windows.defender" `
        -ObservedValue $status `
        -SourceLocator "Get-MpComputerStatus"
}

# WinRM configuration
$winrmService = winrm get winrm/config/service 2>$null | Out-String
if ($winrmService) {
    Add-Evidence `
        -ControlId "windows.remote_management" `
        -Category "windows.winrm" `
        -ObservedValue ($winrmService.Trim()) `
        -SourceLocator "winrm get winrm/config/service"
}

# Important note:
# The collector gathers evidence only. It does not automatically declare
# every returned value insecure. VulnForge's deterministic rule engine
# performs the assessment.

$result = [PSCustomObject]@{
    evidence = $evidence
}

$result |
    ConvertTo-Json -Depth 8 |
    Set-Content -Encoding UTF8 $OutputPath

Write-Host "V10 evidence written to $OutputPath"
