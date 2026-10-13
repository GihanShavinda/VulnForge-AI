from app.services.web_redaction import redact_headers, redact_structure, redact_text, redact_url


def test_redacts_sensitive_headers():
    result = redact_headers({
        "Authorization": "Bearer secret",
        "Cookie": "session=abc",
        "Server": "nginx",
    })
    assert result["Authorization"] == "[REDACTED]"
    assert result["Cookie"] == "[REDACTED]"
    assert result["Server"] == "nginx"


def test_redacts_tokens_from_url():
    url = redact_url("https://example.test/path?token=abc123&x=1")
    assert "abc123" not in url
    assert "[REDACTED]" in url


def test_redacts_nested_sensitive_keys():
    result = redact_structure({
        "request": {
            "session_id": "abc",
            "headers": {"Authorization": "Basic xxx"},
            "method": "GET",
        }
    })
    assert result["request"]["session_id"] == "[REDACTED]"
    assert result["request"]["headers"]["Authorization"] == "[REDACTED]"


def test_redacts_raw_cookie_line():
    text = redact_text("Cookie: session=super-secret\nServer: test")
    assert "super-secret" not in text
