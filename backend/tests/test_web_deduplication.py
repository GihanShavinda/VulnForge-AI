from app.services.web_deduplication import build_dedupe_key


def test_equivalent_findings_from_different_scanners_dedupe():
    zap = build_dedupe_key(
        url="https://example.test/admin/",
        method="GET",
        title="Directory Listing",
        finding_type=None,
        parameter=None,
    )
    nikto = build_dedupe_key(
        url="https://example.test/admin",
        method="GET",
        title="Directory indexing enabled",
        finding_type=None,
        parameter=None,
    )
    assert zap == nikto


def test_different_parameters_do_not_dedupe():
    first = build_dedupe_key(
        url="https://example.test/search",
        method="GET",
        title="Cross Site Scripting",
        finding_type=None,
        parameter="q",
    )
    second = build_dedupe_key(
        url="https://example.test/search",
        method="GET",
        title="Cross Site Scripting",
        finding_type=None,
        parameter="name",
    )
    assert first != second
