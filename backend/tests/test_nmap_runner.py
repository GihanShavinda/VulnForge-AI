from pathlib import Path

from app.services.nmap_runner import (
    build_discovery_command,
    get_nmap_executable,
)


def test_icmp_command_generates_xml_output():
    output_file = Path("scan.xml")

    command = build_discovery_command(
        "192.168.56.0/24",
        "icmp",
        output_file,
    )

    assert command[0] == get_nmap_executable()
    assert "-sn" in command
    assert "-PE" in command
    assert "-PP" in command
    assert "-PM" in command
    assert "-oX" in command
    assert str(output_file) in command
    assert command[-1] == "192.168.56.0/24"


def test_arp_command_uses_arp_discovery():
    output_file = Path("scan.xml")

    command = build_discovery_command(
        "192.168.56.0/24",
        "arp",
        output_file,
    )

    assert command[0] == get_nmap_executable()
    assert "-sn" in command
    assert "-PR" in command
    assert "-oX" in command
    assert str(output_file) in command
    assert command[-1] == "192.168.56.0/24"


def test_tcp_command_uses_tcp_discovery_probes():
    output_file = Path("scan.xml")

    command = build_discovery_command(
        "192.168.56.0/24",
        "tcp",
        output_file,
    )

    assert command[0] == get_nmap_executable()
    assert "-sn" in command
    assert "-PS80,443,445,3389" in command
    assert "-PA80,443" in command
    assert "-oX" in command
    assert str(output_file) in command
    assert command[-1] == "192.168.56.0/24"