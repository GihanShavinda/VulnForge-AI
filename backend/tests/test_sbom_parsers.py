from app.services.sbom_parsers import parse_sbom


def test_cyclonedx_component_normalization():
    document = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "bom-ref": "pkg:pypi/requests@2.31.0",
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "supplier": {"name": "Example Supplier"},
            }
        ],
    }
    components, findings = parse_sbom("cyclonedx", document)
    assert len(components) == 1
    assert components[0].name == "requests"
    assert components[0].ecosystem == "pypi"
    assert findings == []


def test_trivy_preserves_direct_vulnerability_match():
    document = {
        "Results": [
            {
                "Target": "rootfs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST-1000",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.2",
                        "FixedVersion": "3.0.3",
                        "PkgIdentifier": {"PURL": "pkg:deb/debian/openssl@3.0.2"},
                    }
                ],
            }
        ]
    }
    components, findings = parse_sbom("trivy", document)
    assert len(components) == 1
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CVE-TEST-1000"
    assert findings[0].fixed_version == "3.0.3"
    assert findings[0].confidence == "confirmed"


def test_os_inventory_text():
    components, findings = parse_sbom(
        "os-package-inventory",
        None,
        "openssl\t3.0.2-0ubuntu1.20\tUbuntu\ncurl\t8.5.0-2ubuntu10\tUbuntu",
    )
    assert len(components) == 2
    assert components[0].ecosystem == "debian"
    assert findings == []
