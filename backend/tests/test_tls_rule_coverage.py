from app.services.tls_rules import evaluate_tls_control

def test_expired_certificate():
    r=evaluate_tls_control("certificate.expired","true",confidence="confirmed")
    assert r is not None
    assert r.finding_type=="certificate_management_problem"
    assert r.severity=="High"

def test_hostname_mismatch():
    r=evaluate_tls_control("certificate.hostname_mismatch","true",confidence="confirmed")
    assert r is not None
    assert r.finding_type=="certificate_management_problem"

def test_weak_cipher():
    r=evaluate_tls_control("cipher.weak","TLS_RSA_WITH_3DES_EDE_CBC_SHA",confidence="confirmed")
    assert r is not None
    assert r.finding_type=="cryptographic_weakness"

def test_chain_issue():
    r=evaluate_tls_control("certificate.chain_issue","missing intermediate",confidence="high confidence")
    assert r is not None
    assert r.finding_type=="certificate_management_problem"

def test_insecure_renegotiation():
    r=evaluate_tls_control("renegotiation.insecure","true",confidence="high confidence")
    assert r is not None
    assert r.severity=="High"
