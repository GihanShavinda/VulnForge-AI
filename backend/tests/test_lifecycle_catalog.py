from datetime import date

from app.services.lifecycle_catalog import lookup_lifecycle


def test_windows_xp_demo_record():
    result = lookup_lifecycle("Microsoft Windows XP", "5.1.2600")
    assert result is not None
    assert result["vendor_support_status"] == "unsupported"
    assert result["end_of_support_date"] == date(2014, 4, 8)


def test_windows_7_demo_record():
    result = lookup_lifecycle("Microsoft Windows 7", "6.1.7601")
    assert result is not None
    assert result["vendor_support_status"] == "unsupported"
    assert result["end_of_support_date"] == date(2020, 1, 14)


def test_unknown_product_not_guessed():
    assert lookup_lifecycle("Unknown Product", "1.0") is None
