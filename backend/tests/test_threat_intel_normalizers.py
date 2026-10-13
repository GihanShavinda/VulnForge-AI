from app.services.threat_intel_normalizers import (
    normalize_cisa_kev,
    normalize_epss,
    normalize_nvd,
    normalize_osv,
)


def test_nvd_normalizes_without_fabricating_missing_values():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0001",
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 8.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}
                        ]
                    },
                    "references": [
                        {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]}
                    ],
                }
            }
        ]
    }
    record = normalize_nvd(payload)[0]
    assert record.cve_id == "CVE-2026-0001"
    assert record.cvss31_score == 8.8
    assert record.cvss4_score is None
    assert record.cwes == ["CWE-79"]
    assert len(record.vendor_advisories) == 1


def test_osv_keeps_osv_and_cve_identity_and_fixed_event():
    payload = {
        "id": "GHSA-test-0000-0000",
        "aliases": ["CVE-2026-0002"],
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-03T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo", "purl": "pkg:pypi/demo"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}],
    }
    record = normalize_osv(payload)[0]
    assert record.canonical_id == "CVE-2026-0002"
    assert record.osv_id == "GHSA-test-0000-0000"
    assert record.cvss31_vector.startswith("CVSS:3.1/")
    assert record.cvss31_score is None
    assert record.fixed_ranges[0]["fixed"] == "2.0.0"
    assert record.cpes == []


def test_cisa_unknown_ransomware_remains_unknown():
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0003",
                "knownRansomwareCampaignUse": "Unknown",
                "requiredAction": "Apply mitigations per vendor instructions.",
            }
        ]
    }
    record = normalize_cisa_kev(payload)[0]
    assert record.kev is True
    assert record.known_ransomware_use is None
    assert record.required_action == "Apply mitigations per vendor instructions."


def test_epss_normalizes_score_and_percentile():
    payload = {
        "data": [
            {
                "cve": "CVE-2026-0004",
                "epss": "0.1234",
                "percentile": "0.8765",
                "date": "2026-10-13",
            }
        ]
    }
    record = normalize_epss(payload)[0]
    assert record.epss == 0.1234
    assert record.epss_percentile == 0.8765
