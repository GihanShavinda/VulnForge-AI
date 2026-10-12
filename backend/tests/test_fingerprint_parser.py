from pathlib import Path

from app.services.fingerprint_parser import candidates_from_http_headers, candidates_from_whatweb, parse_nmap_os_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_os_sample.xml"


def test_parse_windows_7_from_nmap_os_evidence():
    candidates = parse_nmap_os_xml(FIXTURE.read_text(encoding="utf-8"))
    rows = [x for x in candidates if x.category == "operating_system"]
    assert any(x.name == "Windows 7" for x in rows)
    assert any(x.confidence == "high confidence" for x in rows)
    assert all(x.version is None for x in rows if x.name == "Windows 7")


def test_http_header_exact_version_requires_header_value():
    candidates = candidates_from_http_headers({"server": "Apache/2.4.58 (Ubuntu)", "x-powered-by": "PHP/8.3.12"}, source_locator="http://192.168.37.20/", raw_evidence="headers")
    assert next(x for x in candidates if x.name == "Apache").version == "2.4.58"
    assert next(x for x in candidates if x.name == "PHP").version == "8.3.12"


def test_header_without_version_does_not_invent_one():
    candidates = candidates_from_http_headers({"server": "nginx"}, source_locator="http://192.168.37.20/", raw_evidence="headers")
    assert next(x for x in candidates if x.name == "Nginx").version is None


def test_whatweb_framework_indicator_without_version_remains_versionless():
    payload = [{"target": "http://192.168.37.20/", "plugins": {"Laravel": {"string": ["Laravel"]}}}]
    candidates = candidates_from_whatweb(payload, source_locator="http://192.168.37.20/", raw_evidence="whatweb-json")
    assert next(x for x in candidates if x.name == "Laravel").version is None
