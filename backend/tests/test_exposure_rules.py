from app.services.exposure_rules import evaluate_exposure_rules


def codes(findings):
    return {x.rule_code for x in findings}


def test_telnet_is_exposure_not_generic_vulnerability_label():
    findings = evaluate_exposure_rules(
        port=23, protocol="tcp", state="open", service="telnet",
        product="Linux telnetd", version=None, banner=None, tls_indicator=False,
        scripts={}, asset_role="legacy-linux-target",
    )
    result = codes(findings)
    assert "TELNET_ENABLED" in result
    assert "LEGACY_SERVICE" in result
    assert "UNENCRYPTED_MANAGEMENT_SERVICE" in result
    assert all("vulnerab" not in x.title.lower() for x in findings)


def test_ftp_anonymous_requires_evidence():
    without = evaluate_exposure_rules(
        port=21, protocol="tcp", state="open", service="ftp", product=None,
        version=None, banner=None, tls_indicator=False, scripts={}, asset_role="server",
    )
    assert "FTP_ANONYMOUS_INDICATOR" not in codes(without)

    with_evidence = evaluate_exposure_rules(
        port=21, protocol="tcp", state="open", service="ftp", product=None,
        version=None, banner=None, tls_indicator=False,
        scripts={"ftp-anon": "Anonymous FTP login allowed (FTP code 230)"},
        asset_role="server",
    )
    assert "FTP_ANONYMOUS_INDICATOR" in codes(with_evidence)


def test_smbv1_requires_protocol_indicator():
    findings = evaluate_exposure_rules(
        port=445, protocol="tcp", state="open", service="microsoft-ds", product="Samba",
        version="3.X", banner=None, tls_indicator=False,
        scripts={"smb-protocols": "NT LM 0.12 (SMBv1)"}, asset_role="server",
    )
    assert "SMBV1_INDICATOR" in codes(findings)


def test_closed_service_produces_no_exposure_findings():
    findings = evaluate_exposure_rules(
        port=3389, protocol="tcp", state="closed", service="ms-wbt-server",
        product=None, version=None, banner=None, tls_indicator=False, scripts={},
        asset_role="legacy-windows-target",
    )
    assert findings == []
