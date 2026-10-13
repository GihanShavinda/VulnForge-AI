from __future__ import annotations

from dataclasses import dataclass

from app.services.web_owasp_mapping import map_to_owasp


@dataclass(frozen=True)
class ClassifiedFinding:
    finding_type: str
    title: str
    severity: str
    confidence: str
    description: str
    remediation: str
    owasp_top10: list[dict]
    mapping_rationale: str


def _contains(text: str, *needles: str) -> bool:
    lower = text.lower()
    return any(n.lower() in lower for n in needles)


def classify(title: str, evidence_text: str | None, severity: str, scanner: str) -> ClassifiedFinding | None:
    text = f"{title} {evidence_text or ''}".strip()

    rules = [
        ("security_headers", ("missing security header", "x-content-type-options", "strict-transport-security"),
         "Add the appropriate security headers after validating application compatibility."),
        ("content_security_policy", ("content security policy", "content-security-policy", "csp header"),
         "Define and test an appropriately restrictive Content-Security-Policy."),
        ("clickjacking_protection", ("clickjacking", "x-frame-options", "frame-ancestors"),
         "Restrict framing with CSP frame-ancestors and/or X-Frame-Options where appropriate."),
        ("tls_configuration", ("weak tls", "ssl", "weak cipher", "tls 1.0", "tls 1.1"),
         "Disable obsolete protocol versions/ciphers and use an approved TLS baseline."),
        ("directory_exposure", ("directory listing", "directory indexing", "directory exposure"),
         "Disable unnecessary directory indexing and restrict exposed paths."),
        ("outdated_web_technology", ("outdated", "end of life", "obsolete web technology"),
         "Upgrade or replace unsupported web technology after compatibility testing."),
        ("cookie_security", ("httponly", "secure cookie", "samesite", "cookie without"),
         "Set appropriate Secure, HttpOnly and SameSite attributes on sensitive cookies."),
        ("authentication_weakness", ("authentication bypass", "weak authentication", "default credential"),
         "Strengthen authentication controls and remove default credentials."),
        ("input_validation", ("sql injection", "cross site scripting", "xss", "command injection", "input validation"),
         "Apply context-appropriate validation/encoding and parameterized APIs."),
        ("information_disclosure", ("information disclosure", "information leak", "stack trace", "debug information"),
         "Remove unnecessary diagnostic or sensitive information from responses."),
        ("dangerous_http_methods", ("trace method", "put method", "delete method", "dangerous http method"),
         "Disable HTTP methods not required by the application."),
        ("default_pages", ("default page", "welcome page", "test page"),
         "Remove default/test pages from production-facing deployments."),
        ("known_vulnerable_components", ("known vulnerable", "vulnerable component", "cve-"),
         "Upgrade the affected component to a supported non-vulnerable version."),
        ("cors_misconfiguration", ("cors", "access-control-allow-origin", "cross-origin"),
         "Restrict CORS origins, methods and credentials to explicitly required values."),
        ("server_banner_disclosure", ("server banner", "server header", "x-powered-by"),
         "Minimize unnecessary server/framework version disclosure."),
    ]

    for finding_type, needles, remediation in rules:
        if _contains(text, *needles):
            owasp, rationale = map_to_owasp(finding_type)
            confidence = "high confidence" if severity.lower() not in {"info", "informational"} else "medium confidence"
            return ClassifiedFinding(
                finding_type=finding_type,
                title=title,
                severity=severity,
                confidence=confidence,
                description=f"Imported {scanner} evidence supports this configuration/application finding.",
                remediation=remediation,
                owasp_top10=owasp,
                mapping_rationale=rationale,
            )
    return None
