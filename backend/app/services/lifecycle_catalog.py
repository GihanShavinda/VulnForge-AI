from __future__ import annotations

from datetime import date


LIFECYCLE_CATALOG = {
    ("Microsoft Windows XP", "5.1"): {
        "vendor_support_status": "unsupported",
        "end_of_support_date": date(2014, 4, 8),
        "patch_availability": "no_standard_vendor_patch",
        "replacement_recommendation": "Replace with a currently supported Windows release. Keep only in an isolated lab if required for research or compatibility testing.",
        "severity": "Critical",
    },
    ("Microsoft Windows 7", "6.1"): {
        "vendor_support_status": "unsupported",
        "end_of_support_date": date(2020, 1, 14),
        "patch_availability": "no_standard_vendor_patch",
        "replacement_recommendation": "Replace with a currently supported Windows release. If retained as a lab target, isolate it and document the accepted legacy risk.",
        "severity": "Critical",
    },
}


def lookup_lifecycle(product: str, version: str | None) -> dict | None:
    normalized_product = product.strip().lower()
    normalized_version = (version or "").strip().lower()

    for (catalog_product, catalog_version), record in LIFECYCLE_CATALOG.items():
        if (
            normalized_product == catalog_product.lower()
            and normalized_version.startswith(catalog_version.lower())
        ):
            return record.copy()

    return None
