from app.services.patch_lifecycle_rules import classify_patch_state, lifecycle_severity


def test_patch_available_state():
    result = classify_patch_state(
        patch_available=True,
        vendor_backport=False,
        compensating_control=None,
    )
    assert result.risk_state == "vulnerable_patch_available"


def test_no_vendor_patch_state():
    result = classify_patch_state(
        patch_available=False,
        vendor_backport=False,
        compensating_control=None,
    )
    assert result.risk_state == "vulnerable_no_vendor_patch"


def test_vendor_backport_state():
    result = classify_patch_state(
        patch_available=True,
        vendor_backport=True,
        compensating_control=None,
    )
    assert result.risk_state == "vendor_backport"


def test_temporary_compensating_control_state():
    result = classify_patch_state(
        patch_available=False,
        vendor_backport=False,
        compensating_control="isolated VLAN and firewall restriction",
    )
    assert result.risk_state == "temporary_compensating_control"


def test_accepted_legacy_with_control_reduces_severity():
    severity = lifecycle_severity(
        vendor_support_status="unsupported",
        accepted_legacy_system=True,
        temporary_compensating_control="isolated lab network",
    )
    assert severity == "Medium"


def test_unsupported_unaccepted_product_is_critical():
    severity = lifecycle_severity(
        vendor_support_status="unsupported",
        accepted_legacy_system=False,
        temporary_compensating_control=None,
    )
    assert severity == "Critical"
