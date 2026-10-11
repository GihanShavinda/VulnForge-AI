from pathlib import Path

from app.services.nmap_service_runner import build_service_command
from app.services.nmap_runner import get_nmap_executable


def test_tcp_service_command_uses_xml_and_version_detection():
    command = build_service_command("192.168.37.129", "tcp", 1000, Path("services.xml"))
    assert command[0] == get_nmap_executable()
    assert "-sT" in command
    assert "-sV" in command
    assert "--version-all" in command
    assert "--top-ports" in command
    assert "1000" in command
    assert "-oX" in command
    assert command[-1] == "192.168.37.129"


def test_udp_service_command_uses_udp_scan():
    command = build_service_command("192.168.37.129", "udp", 100, Path("services.xml"))
    assert "-sU" in command
    assert "-sT" not in command
    assert "100" in command
