from app.services.tls_rules import evaluate_tls_control

def test_sslv3_is_critical_crypto_weakness():
    r=evaluate_tls_control("protocol.sslv3","enabled",confidence="confirmed")
    assert r is not None
    assert r.finding_type=="cryptographic_weakness"
    assert r.severity=="Critical"

def test_tls10_is_high():
    r=evaluate_tls_control("protocol.tls1_0","true",confidence="confirmed")
    assert r is not None
    assert r.severity=="High"

def test_short_key_size_detected():
    r=evaluate_tls_control("certificate.key_bits","1024",confidence="confirmed")
    assert r is not None
    assert r.finding_type=="cryptographic_weakness"

def test_self_signed_lab_certificate_not_critical():
    r=evaluate_tls_control("certificate.self_signed","true",confidence="confirmed",lab_context=True)
    assert r is not None
    assert r.acceptable_lab_configuration is True
    assert r.severity=="Low"

def test_self_signed_production_is_management_problem():
    r=evaluate_tls_control("certificate.self_signed","true",confidence="confirmed",lab_context=False)
    assert r is not None
    assert r.finding_type=="certificate_management_problem"
    assert r.severity=="Medium"

def test_supported_modern_protocol_produces_no_finding():
    assert evaluate_tls_control("protocol.tls1_0","disabled",confidence="confirmed") is None
