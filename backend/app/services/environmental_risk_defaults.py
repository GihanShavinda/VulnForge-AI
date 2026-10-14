from __future__ import annotations


DEFAULT_VERSION_KEY = "ers-2.0-experimental"

DEFAULT_WEIGHTS = {
    "technical_severity": 0.12,
    "exploit_probability": 0.09,
    "known_exploitation": 0.10,
    "network_exposure": 0.08,
    "service_reachability": 0.08,
    "asset_criticality": 0.10,
    "attack_path_importance": 0.10,
    "privilege_impact": 0.06,
    "credential_exposure": 0.06,
    "security_control_weakness": 0.05,
    "patch_unavailability": 0.05,
    "threat_relevance": 0.04,
    "evidence_confidence": 0.03,
    "lifecycle_risk": 0.04,
}

DEFAULT_INTERACTION_RULES = {
    "exposed_kev_critical_path_bonus": 12.0,
    "isolated_nonreachable_strong_control_penalty": -20.0,
}

DEFAULT_DESCRIPTION = (
    "Experimental Environmental Risk Score 2.0. "
    "Combines technical severity with exploitability, exposure, asset context, "
    "attack-path importance, credentials, controls, patch posture, threat relevance, "
    "evidence confidence, and lifecycle risk. This is not a CVSS replacement."
)
