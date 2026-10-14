EFFECT_MULTIPLIERS = {
    "prevents": 1.00,
    "reduces": 0.70,
    "detects": 0.20,
    "contains": 0.50,
    "does_not_affect": 0.00,
}

CONTROL_EXPOSURE_MATRIX = {
    "host_firewall": {"network_service":"reduces","lateral_movement":"contains","administrative_access":"reduces"},
    "network_segmentation": {"network_service":"reduces","lateral_movement":"contains","administrative_access":"reduces"},
    "authentication_requirement": {"web_application":"reduces","network_service":"reduces","administrative_access":"prevents"},
    "edr_av": {"malware_execution":"detects","lateral_movement":"detects","vulnerability_exploitability":"detects"},
    "mfa": {"credential_exposure":"reduces","administrative_access":"prevents","web_application":"reduces"},
    "reverse_proxy": {"web_application":"reduces","network_service":"reduces"},
    "waf": {"web_application":"reduces","vulnerability_exploitability":"reduces"},
    "least_privilege": {"privilege_escalation":"contains","credential_exposure":"contains","lateral_movement":"contains"},
    "service_disabled": {"network_service":"prevents","vulnerability_exploitability":"prevents"},
    "acl": {"network_service":"reduces","administrative_access":"prevents","lateral_movement":"contains"},
    "patch": {"vulnerability_exploitability":"prevents"},
    "tls": {"transport_security":"prevents","credential_exposure":"reduces"},
    "application_allow_listing": {"malware_execution":"prevents","lateral_movement":"contains"},
    "restricted_admin_access": {"administrative_access":"prevents","privilege_escalation":"reduces","lateral_movement":"contains"},
}

def determine_control_effect(control_type: str, exposure_type: str) -> str:
    return CONTROL_EXPOSURE_MATRIX.get(control_type, {}).get(exposure_type, "does_not_affect")
