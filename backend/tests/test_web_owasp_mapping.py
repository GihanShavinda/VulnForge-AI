from app.services.web_owasp_mapping import map_to_owasp


def test_input_validation_maps_to_injection():
    refs, rationale = map_to_owasp("input_validation")
    assert refs[0]["id"] == "A03:2021"
    assert rationale


def test_known_component_maps_to_a06():
    refs, _ = map_to_owasp("known_vulnerable_components")
    assert refs[0]["id"] == "A06:2021"


def test_unsupported_mapping_returns_empty():
    refs, rationale = map_to_owasp("unsupported")
    assert refs == []
    assert "No OWASP" in rationale
