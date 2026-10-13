from app.services.weakness_attack_catalog import (
    get_attack_technique,
    get_capec_for_cwe,
    get_potential_techniques,
)


def test_supported_cwe_to_capec():
    rows = get_capec_for_cwe("CWE-79")
    assert rows
    assert rows[0]["capec_id"] == "CAPEC-63"


def test_unsupported_cwe_mapping_returns_empty():
    assert get_capec_for_cwe("CWE-999999") == []


def test_supported_potential_attack_mapping():
    rows = get_potential_techniques("cwe", "CWE-78")
    assert rows
    assert rows[0]["attack_id"] == "T1059"


def test_unsupported_attack_mapping_returns_empty():
    assert get_potential_techniques("cwe", "CWE-999999") == []


def test_attack_subtechnique_metadata():
    row = get_attack_technique("T1059.001")
    assert row is not None
    assert row["subtechnique_of"] == "T1059"
    assert row["tactic"] == "Execution"


def test_unknown_attack_technique_returns_none():
    assert get_attack_technique("T9999") is None
