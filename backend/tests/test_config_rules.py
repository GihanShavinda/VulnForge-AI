from app.services.config_rules import evaluate_control


def test_linux_root_ssh_login_finding():
    result = evaluate_control(
        "linux.root_ssh_login",
        "PermitRootLogin yes",
        {"source": "sshd_config"},
        "confirmed",
    )
    assert result is not None
    assert result.severity == "High"
    assert "root" in result.control.lower()


def test_linux_firewall_enabled_passes_when_enabled():
    result = evaluate_control(
        "linux.firewall_enabled",
        "enabled",
        {"source": "ufw"},
        "confirmed",
    )
    assert result is None


def test_windows_smbv1_finding():
    result = evaluate_control(
        "windows.smbv1",
        "SMBv1 enabled",
        {"source": "PowerShell"},
        "confirmed",
    )
    assert result is not None
    assert result.severity == "Critical"


def test_windows_guest_disabled_passes():
    result = evaluate_control(
        "windows.guest_account",
        "disabled",
        {"source": "PowerShell"},
        "confirmed",
    )
    assert result is None


def test_unsupported_control_returns_none():
    result = evaluate_control(
        "unsupported.control",
        "anything",
        {},
        "high confidence",
    )
    assert result is None
