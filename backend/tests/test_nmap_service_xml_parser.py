from pathlib import Path

from app.services.nmap_service_xml_parser import parse_nmap_service_xml

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_service_evidence():
    xml = (FIXTURES / "nmap_services_sample.xml").read_text(encoding="utf-8")
    _, services = parse_nmap_service_xml(xml)

    assert len(services) == 6
    ftp = next(x for x in services if x.port == 21)
    assert ftp.protocol == "tcp"
    assert ftp.state == "open"
    assert ftp.service == "ftp"
    assert ftp.product == "vsftpd"
    assert ftp.version == "2.3.4"
    assert ftp.banner == "220 (vsFTPd 2.3.4)"
    assert ftp.cpe == "cpe:/a:vsftpd:vsftpd:2.3.4"
    assert ftp.scan_confidence == 10
    assert "ftp-anon" in ftp.script_outputs

    https = next(x for x in services if x.port == 443)
    assert https.tls_indicator is True


def test_parse_closed_port_state():
    xml = (FIXTURES / "nmap_services_changed.xml").read_text(encoding="utf-8")
    _, services = parse_nmap_service_xml(xml)
    postgres = next(x for x in services if x.port == 5432)
    assert postgres.state == "closed"
