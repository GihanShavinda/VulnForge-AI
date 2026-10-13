from __future__ import annotations

OWASP_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

FINDING_TO_OWASP = {
    "security_headers": [("A05:2021", "Security header weakness is a security configuration issue.")],
    "tls_configuration": [("A02:2021", "Weak TLS configuration can contribute to cryptographic failures.")],
    "directory_exposure": [("A05:2021", "Directory listing/exposure is a security misconfiguration.")],
    "outdated_web_technology": [("A06:2021", "Outdated software can represent vulnerable and outdated components.")],
    "cookie_security": [("A05:2021", "Missing cookie security attributes are commonly a configuration weakness.")],
    "authentication_weakness": [("A07:2021", "Evidence-supported authentication weakness maps to identification/authentication failures.")],
    "input_validation": [("A03:2021", "Scanner-reported injection/input validation evidence maps to Injection when supported.")],
    "information_disclosure": [("A05:2021", "Information disclosure through configuration/default behavior maps to security misconfiguration.")],
    "dangerous_http_methods": [("A05:2021", "Unnecessary dangerous HTTP methods are a security misconfiguration.")],
    "default_pages": [("A05:2021", "Default content/pages indicate security misconfiguration.")],
    "known_vulnerable_components": [("A06:2021", "Known vulnerable components map to vulnerable and outdated components.")],
    "cors_misconfiguration": [("A01:2021", "Evidence-supported CORS weakness can enable unauthorized cross-origin access.")],
    "content_security_policy": [("A05:2021", "Missing/weak CSP is treated as security misconfiguration context.")],
    "clickjacking_protection": [("A05:2021", "Missing frame restrictions are treated as security misconfiguration context.")],
    "server_banner_disclosure": [("A05:2021", "Detailed server banner disclosure is a security misconfiguration.")],
}


def map_to_owasp(finding_type: str) -> tuple[list[dict], str]:
    mappings = FINDING_TO_OWASP.get(finding_type, [])
    refs = [{"id": key, "name": OWASP_2021[key]} for key, _ in mappings]
    rationale = " ".join(reason for _, reason in mappings)
    return refs, rationale or "No OWASP Top 10 mapping asserted because evidence is insufficient or unsupported."
