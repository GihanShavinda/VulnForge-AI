from app.services.fingerprint_confidence import FingerprintCandidate, aggregate_candidates


def c(category: str, name: str, version: str | None, confidence: str, source: str) -> FingerprintCandidate:
    return FingerprintCandidate(category, name, version, confidence, source, f"{name} {version or ''}".strip(), "test", "test evidence")


def test_confirmed_authenticated_inventory_wins():
    result = aggregate_candidates([c("operating_system", "Ubuntu", "24.04", "confirmed", "authenticated_inventory"), c("operating_system", "Ubuntu", None, "medium confidence", "nmap_os")])
    assert result[0].confidence == "confirmed"
    assert result[0].version == "24.04"
    assert result[0].is_preferred is True


def test_conflicting_os_evidence_is_marked():
    result = aggregate_candidates([c("operating_system", "Windows 7", None, "high confidence", "nmap_os"), c("operating_system", "Ubuntu", "18.04", "medium confidence", "http_header")])
    assert len(result) == 2
    assert all(x.conflict_state == "conflicting" for x in result)
    assert sum(1 for x in result if x.is_preferred) == 1


def test_conflicting_equally_strong_versions_are_not_guessed():
    result = aggregate_candidates([c("web_server", "Apache", "2.4.57", "high confidence", "service_banner"), c("web_server", "Apache", "2.4.58", "high confidence", "service_banner")])
    assert result[0].version is None
    assert result[0].conflict_state == "conflicting"


def test_missing_version_stays_unknown():
    result = aggregate_candidates([c("framework", "Laravel", None, "low confidence", "whatweb")])
    assert result[0].version is None
