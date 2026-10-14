from app.services.security_control_matrix import determine_control_effect

def test_control_effects():
    assert determine_control_effect("service_disabled","network_service") == "prevents"
    assert determine_control_effect("waf","web_application") == "reduces"
    assert determine_control_effect("edr_av","malware_execution") == "detects"
    assert determine_control_effect("network_segmentation","lateral_movement") == "contains"
    assert determine_control_effect("tls","web_application") == "does_not_affect"
