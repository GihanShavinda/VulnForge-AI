import pytest

from app.services.attack_graph_validation import (
    validate_node_label,
    validate_relationship_type,
    validate_scenario,
)


def test_valid_node_and_relationship():
    assert validate_node_label("Asset") == "Asset"
    assert validate_relationship_type("EXPOSES") == "EXPOSES"


def test_invalid_label_rejected():
    with pytest.raises(ValueError):
        validate_node_label("AttackerMachine")


def test_invalid_relationship_rejected():
    with pytest.raises(ValueError):
        validate_relationship_type("EXPLOITS")


def test_supported_scenarios():
    assert validate_scenario("internet") == "internet"
    assert validate_scenario("kali_lab_attacker") == "kali_lab_attacker"
    assert validate_scenario("low_privilege_internal_user") == "low_privilege_internal_user"
    assert validate_scenario("compromised_workstation") == "compromised_workstation"
