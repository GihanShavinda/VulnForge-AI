from __future__ import annotations


SCENARIO_START_NODES = {
    "internet": {
        "key": "scenario:internet",
        "label": "TrustBoundary",
        "name": "Internet-style Starting Point",
        "properties": {
            "scenario": "internet",
            "exposure": "external",
            "theoretical": True,
        },
    },
    "kali_lab_attacker": {
        "key": "scenario:kali-lab-attacker",
        "label": "Asset",
        "name": "Kali Lab Attacker",
        "properties": {
            "scenario": "kali_lab_attacker",
            "exposure": "lab",
            "authorized_lab_attacker": True,
        },
    },
    "low_privilege_internal_user": {
        "key": "scenario:low-priv-user",
        "label": "UserRole",
        "name": "Low-Privilege Internal User",
        "properties": {
            "scenario": "low_privilege_internal_user",
            "exposure": "internal",
            "privilege": "low",
        },
    },
    "compromised_workstation": {
        "key": "scenario:compromised-workstation",
        "label": "Asset",
        "name": "Compromised Workstation Scenario",
        "properties": {
            "scenario": "compromised_workstation",
            "exposure": "internal",
            "compromise_assumed": True,
        },
    },
}


def scenario_start_node(scenario: str) -> dict:
    try:
        return SCENARIO_START_NODES[scenario]
    except KeyError as exc:
        raise ValueError(f"Unsupported scenario: {scenario}") from exc
