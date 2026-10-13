from app.services.config_evidence_parsers import (
    parse_lynis_report,
    parse_openscap_json,
    parse_powershell_json,
    parse_simple_control_lines,
)


def test_parse_lynis_key_value_lines():
    rows = parse_lynis_report(
        """
        # comment
        firewall-active=0
        ssh-daemon-status=running
        """
    )
    assert len(rows) == 2
    assert rows[0]["category"] == "lynis.firewall-active"


def test_parse_openscap_json():
    rows = parse_openscap_json(
        {
            "results": [
                {
                    "id": "xccdf_rule_test",
                    "result": "fail",
                    "title": "Example",
                    "evidence": "observed",
                }
            ]
        }
    )
    assert len(rows) == 1
    assert rows[0]["source_locator"] == "xccdf_rule_test"
    assert rows[0]["observed_value"] == "fail"


def test_parse_powershell_json():
    rows = parse_powershell_json(
        {
            "evidence": [
                {
                    "control_id": "windows.smbv1",
                    "category": "windows.smb",
                    "observed_value": "SMBv1 enabled",
                }
            ]
        }
    )
    assert len(rows) == 1
    assert rows[0]["control_id"] == "windows.smbv1"
    assert rows[0]["confidence"] == "confirmed"


def test_parse_simple_control_lines():
    rows = parse_simple_control_lines(
        "linux.firewall_enabled\tdisabled\nlinux.root_ssh_login\tPermitRootLogin yes"
    )
    assert len(rows) == 2
    assert rows[1]["control_id"] == "linux.root_ssh_login"
