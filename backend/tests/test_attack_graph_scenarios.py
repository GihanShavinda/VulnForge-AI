from app.services.attack_graph_scenarios import scenario_start_node


def test_internet_start():
    row = scenario_start_node("internet")
    assert row["label"] == "TrustBoundary"
    assert row["key"] == "scenario:internet"


def test_kali_start():
    row = scenario_start_node("kali_lab_attacker")
    assert row["label"] == "Asset"
    assert row["properties"]["authorized_lab_attacker"] is True


def test_low_privilege_user_start():
    row = scenario_start_node("low_privilege_internal_user")
    assert row["label"] == "UserRole"
    assert row["properties"]["privilege"] == "low"


def test_compromised_workstation_start():
    row = scenario_start_node("compromised_workstation")
    assert row["label"] == "Asset"
    assert row["properties"]["compromise_assumed"] is True
