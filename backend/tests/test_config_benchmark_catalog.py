from app.services.config_benchmark_catalog import BENCHMARK_PROFILES


def test_required_profiles_exist():
    assert {
        "Legacy Lab",
        "Standard Workstation",
        "Linux Server",
        "Windows Workstation",
        "Web Server",
    }.issubset(BENCHMARK_PROFILES)


def test_linux_server_contains_expected_controls():
    controls = BENCHMARK_PROFILES["Linux Server"]["controls"]
    assert "linux.root_ssh_login" in controls
    assert "linux.firewall_enabled" in controls
    assert "linux.weak_ssh_algorithms" in controls


def test_windows_workstation_contains_expected_controls():
    controls = BENCHMARK_PROFILES["Windows Workstation"]["controls"]
    assert "windows.guest_account" in controls
    assert "windows.smbv1" in controls
    assert "windows.remote_management" in controls
