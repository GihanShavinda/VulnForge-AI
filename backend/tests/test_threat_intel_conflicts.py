from app.services.threat_intel_conflicts import detect_conflicting_values


def test_same_values_do_not_conflict():
    assert detect_conflicting_values({"NVD": 8.8, "OSV": 8.8}) is False


def test_different_non_null_values_conflict():
    assert detect_conflicting_values({"NVD": 8.8, "OSV": 9.1}) is True


def test_missing_value_does_not_create_conflict():
    assert detect_conflicting_values({"NVD": 8.8, "OSV": None}) is False
