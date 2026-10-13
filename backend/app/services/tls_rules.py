from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class TLSRuleResult:
    finding_type: str
    control: str
    observed_state: str
    severity: str
    remediation: str
    confidence: str
    acceptable_lab_configuration: bool
    rationale: str

def _truthy(v: str) -> bool:
    return v.strip().lower() in {"true","yes","enabled","supported","present","1"}

def evaluate_tls_control(category: str, observed_value: str, *, confidence: str, lab_context: bool=False) -> TLSRuleResult | None:
    c = category.strip().lower()
    v = observed_value.strip()
    low = v.lower()

    if c == "protocol.sslv2" and _truthy(v):
        return TLSRuleResult("cryptographic_weakness","Disable SSLv2",v,"Critical",
            "Disable SSLv2 and restrict the service to modern TLS versions.",confidence,False,
            "SSLv2 is obsolete and cryptographically unsafe.")

    if c == "protocol.sslv3" and _truthy(v):
        return TLSRuleResult("cryptographic_weakness","Disable SSLv3",v,"Critical",
            "Disable SSLv3 and restrict the service to modern TLS versions.",confidence,False,
            "SSLv3 is obsolete and vulnerable to known protocol weaknesses.")

    if c == "protocol.tls1_0" and _truthy(v):
        return TLSRuleResult("cryptographic_weakness","Disable TLS 1.0",v,"High",
            "Disable TLS 1.0 after validating client compatibility.",confidence,False,
            "TLS 1.0 is obsolete and should not remain enabled on modern services.")

    if c == "protocol.tls1_1" and _truthy(v):
        return TLSRuleResult("cryptographic_weakness","Disable TLS 1.1",v,"Medium",
            "Disable TLS 1.1 after validating client compatibility.",confidence,False,
            "TLS 1.1 is obsolete and generally unnecessary on modern services.")

    if c == "cipher.weak" and low not in {"none","[]","0","false","disabled"}:
        return TLSRuleResult("cryptographic_weakness","Remove weak TLS ciphers",v,"High",
            "Remove deprecated or weak cipher suites and use the approved TLS baseline.",confidence,False,
            "Scanner evidence reports weak or deprecated cryptographic suites.")

    if c == "certificate.expired" and _truthy(v):
        return TLSRuleResult("certificate_management_problem","Renew expired certificate",v,"High",
            "Replace the expired certificate with a valid certificate and verify the full chain.",confidence,False,
            "An expired certificate is a certificate-management failure.")

    if c == "certificate.hostname_mismatch" and _truthy(v):
        return TLSRuleResult("certificate_management_problem","Correct certificate hostname coverage",v,"High",
            "Issue a certificate whose SAN/CN covers the intended service hostname.",confidence,False,
            "The certificate identity does not match the assessed hostname.")

    if c == "certificate.self_signed" and _truthy(v):
        return TLSRuleResult("certificate_management_problem","Review self-signed certificate trust",v,
            "Low" if lab_context else "Medium",
            "For production, use an approved trusted certificate chain. In an isolated lab, document and pin the self-signed certificate if intentionally used.",
            confidence,lab_context,
            "A self-signed certificate is not automatically critical. In an isolated lab it can be acceptable when intentionally trusted and documented.")

    if c == "certificate.key_bits":
        try:
            bits=int(v)
        except ValueError:
            return None
        if bits < 2048:
            return TLSRuleResult("cryptographic_weakness","Use adequate certificate key size",v,"High",
                "Replace the certificate/key with an approved key size, typically RSA 2048+ or an approved ECC equivalent.",
                confidence,False,f"Observed certificate key size is {bits} bits, below the safety threshold.")

    if c == "certificate.chain_issue" and low not in {"none","false","ok","valid"}:
        return TLSRuleResult("certificate_management_problem","Repair certificate chain",v,"Medium",
            "Install required intermediate certificates and validate the full trust chain.",confidence,False,
            "Scanner evidence indicates a certificate-chain validation problem.")

    if c == "certificate.trust" and low in {"untrusted","unknown","failed","invalid"}:
        return TLSRuleResult("certificate_management_problem","Establish certificate trust",v,
            "Low" if lab_context else "Medium",
            "Use an approved trust chain in production, or document/pin intentional lab trust exceptions.",
            confidence,lab_context,
            "Certificate trust failed. In a controlled lab this can be acceptable if intentional and documented.")

    if c == "certificate.age_days":
        try:
            age=int(v)
        except ValueError:
            return None
        if age > 825:
            return TLSRuleResult("certificate_management_problem","Review unusually old certificate",v,"Low",
                "Review certificate issuance and rotation practices and replace if outside policy.",
                confidence,lab_context,
                f"Certificate age is {age} days; age is a management indicator, not a cryptographic break by itself.")

    if c == "renegotiation.insecure" and _truthy(v):
        return TLSRuleResult("cryptographic_weakness","Disable insecure TLS renegotiation",v,"High",
            "Disable insecure renegotiation or upgrade the TLS stack.",confidence,False,
            "Scanner evidence reports insecure renegotiation support.")

    return None
