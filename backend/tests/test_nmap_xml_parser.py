from pathlib import Path

from app.services.nmap_xml_parser import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_stored_nmap_xml_fixture():
    xml = (FIXTURES / "nmap_discovery_sample.xml").read_text(encoding="utf-8")
    timestamp, hosts = parse_nmap_xml(xml)

    assert timestamp.tzinfo is not None
    assert len(hosts) == 2

    first = hosts[0]
    assert first.ip_address == "192.168.56.20"
    assert first.hostname == "metasploitable2.lab"
    assert first.mac_address == "00:0C:29:AA:BB:CC"
    assert first.vendor == "VMware"
    assert first.reachable is True
    assert first.state == "up"


def test_changed_fixture_preserves_new_observations():
    xml = (FIXTURES / "nmap_discovery_changed.xml").read_text(encoding="utf-8")
    _, hosts = parse_nmap_xml(xml)
    assert {h.ip_address for h in hosts} == {"192.168.56.25", "192.168.56.41"}
