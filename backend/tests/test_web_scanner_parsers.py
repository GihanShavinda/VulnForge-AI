import json

from app.services.web_scanner_parsers import parse_nikto, parse_nuclei, parse_whatweb, parse_zap


def test_parse_zap_and_redact_authorization():
    rows = parse_zap({
        "alerts": [{
            "pluginid": "10020",
            "alert": "Missing Security Header",
            "risk": "Medium",
            "instances": [{
                "uri": "https://example.test/",
                "method": "GET",
                "requestHeader": "Authorization: Bearer secret-token",
                "responseHeader": "Server: nginx",
                "evidence": "X-Content-Type-Options missing",
            }],
        }]
    })
    assert len(rows) == 1
    assert "secret-token" not in str(rows[0]["request_metadata"])


def test_parse_nikto_json():
    rows = parse_nikto({
        "items": [{
            "id": "001",
            "url": "https://example.test/",
            "msg": "Server banner disclosure",
        }]
    })
    assert rows[0]["scanner"] == "nikto"


def test_parse_nuclei_jsonl():
    payload = "\n".join([
        json.dumps({
            "template-id": "http-missing-security-headers",
            "matched-at": "https://example.test/",
            "info": {"name": "Missing Security Header", "severity": "low"},
            "request": "GET / HTTP/1.1\nAuthorization: Bearer abc",
        })
    ])
    rows = parse_nuclei(payload)
    assert len(rows) == 1
    assert "Bearer abc" not in str(rows[0]["request_metadata"])


def test_parse_whatweb_json():
    rows = parse_whatweb([{
        "target": "https://example.test/",
        "plugins": {
            "Apache": {"version": ["2.4.49"]}
        },
    }])
    assert len(rows) == 1
    assert "Apache" in rows[0]["title"]
