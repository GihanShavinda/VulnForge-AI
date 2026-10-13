import json
from app.services.tls_scanner_parsers import parse_testssl, parse_sslscan, parse_nmap_ssl

def test_testssl_parser():
    rows=parse_testssl([
        {"id":"SSLv3","finding":"enabled"},
        {"id":"cipher_test","finding":"weak cipher"}
    ])
    cats={x["category"] for x in rows}
    assert "protocol.sslv3" in cats
    assert "cipher.weak" in cats

def test_sslscan_parser():
    xml='<document ssl2="false" ssl3="true" tls10="true" tls11="false"><certificate selfSigned="true" keySize="1024"/></document>'
    rows=parse_sslscan(xml)
    cats={x["category"] for x in rows}
    assert "protocol.sslv3" in cats
    assert "certificate.self_signed" in cats
    assert "certificate.key_bits" in cats

def test_nmap_ssl_parser():
    xml='<nmaprun><host><ports><port><script id="ssl-enum-ciphers" output="SSLv3: TLS_RSA_WITH_3DES_EDE_CBC_SHA"/><script id="ssl-cert" output="Subject: CN=test Public Key bits: 1024 self-signed"/></port></ports></host></nmaprun>'
    rows=parse_nmap_ssl(xml)
    cats={x["category"] for x in rows}
    assert "protocol.sslv3" in cats
    assert "cipher.weak" in cats
    assert "certificate.self_signed" in cats
    assert "certificate.key_bits" in cats
