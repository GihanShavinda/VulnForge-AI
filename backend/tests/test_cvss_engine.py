import pytest

from app.services.cvss_engine import parse_cvss


def test_parse_cvss31_vector():
    result = parse_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result.version == "3.1"
    assert result.base_score == 9.8
    assert result.severity == "Critical"
    assert result.components["attack_vector"]["label"] == "Network"
    assert result.components["scope"]["label"] == "Unchanged"


def test_parse_cvss40_vector():
    result = parse_cvss(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )
    assert result.version == "4.0"
    assert result.base_score >= 0
    assert result.components["attack_requirements"]["label"] == "None"
    assert result.components["vulnerable_system_confidentiality"]["label"] == "High"


def test_cvss_version_not_silently_converted():
    with pytest.raises(ValueError):
        parse_cvss("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_invalid_vector_rejected():
    with pytest.raises(ValueError):
        parse_cvss("AV:N/AC:L")
