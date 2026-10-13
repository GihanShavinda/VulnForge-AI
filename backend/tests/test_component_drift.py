from app.services.component_drift import detect_component_drift
from app.services.sbom_types import NormalizedComponent


def test_component_drift_added_removed_and_version_changed():
    previous = [
        NormalizedComponent(name="a", version="1.0.0", ecosystem="pypi"),
        NormalizedComponent(name="b", version="1.0.0", ecosystem="pypi"),
    ]
    current = [
        NormalizedComponent(name="a", version="2.0.0", ecosystem="pypi"),
        NormalizedComponent(name="c", version="1.0.0", ecosystem="pypi"),
    ]

    events = detect_component_drift(previous, current)
    summary = {(x.identity_key, x.change_type, x.previous_version, x.current_version) for x in events}

    assert ("name:pypi:a", "version_changed", "1.0.0", "2.0.0") in summary
    assert ("name:pypi:b", "removed", "1.0.0", None) in summary
    assert ("name:pypi:c", "added", None, "1.0.0") in summary
