from app.schemas.patch_lifecycle import LifecycleObservation, PatchObservation


def test_patch_observation_tracks_reboot_and_backport():
    row = PatchObservation(
        component="openssl",
        installed_version="1.0",
        fixed_version="1.1",
        vulnerability_id="CVE-LAB-0001",
        severity="High",
        patch_available=True,
        reboot_required=False,
        vendor_backport=True,
    )
    assert row.vendor_backport is True
    assert row.reboot_required is False


def test_lifecycle_observation_tracks_required_fields():
    row = LifecycleObservation(
        product="Microsoft Windows 7",
        version="6.1.7601",
        category="operating_system",
        vendor_support_status="unsupported",
        end_of_support_date="2020-01-14",
        patch_availability="no_standard_vendor_patch",
        accepted_legacy_system=True,
        temporary_compensating_control="isolated host-only VMware network",
        vendor_backport=False,
        replacement_recommendation="Replace with a supported Windows release.",
    )
    assert row.accepted_legacy_system is True
    assert row.end_of_support_date.isoformat() == "2020-01-14"
