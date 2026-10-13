from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PatchRiskResult:
    risk_state: str
    remediation: str


def classify_patch_state(
    *,
    patch_available: bool | None,
    vendor_backport: bool,
    compensating_control: str | None,
) -> PatchRiskResult:
    if vendor_backport:
        return PatchRiskResult(
            "vendor_backport",
            "Verify the vendor backport is installed and documented. Do not require an upstream version match when the vendor has backported the security fix.",
        )

    if patch_available is True:
        if compensating_control:
            return PatchRiskResult(
                "temporary_compensating_control",
                "Keep the temporary compensating control in place only until the approved patch is deployed, then verify remediation.",
            )
        return PatchRiskResult(
            "vulnerable_patch_available",
            "Apply the vendor-supported patch or fixed package version through the normal change process and verify the result.",
        )

    if patch_available is False:
        if compensating_control:
            return PatchRiskResult(
                "temporary_compensating_control",
                "No vendor patch is currently available. Maintain the documented compensating control, reduce exposure, and monitor for a vendor fix or replacement path.",
            )
        return PatchRiskResult(
            "vulnerable_no_vendor_patch",
            "No vendor patch is currently available. Reduce exposure, apply compensating controls, and evaluate product replacement.",
        )

    return PatchRiskResult(
        "patch_status_unknown",
        "Confirm vendor patch status before prioritizing remediation.",
    )


def lifecycle_severity(
    *,
    vendor_support_status: str,
    accepted_legacy_system: bool,
    temporary_compensating_control: str | None,
) -> str:
    status = vendor_support_status.strip().lower()

    if status in {"unsupported", "end-of-life", "eol"}:
        if accepted_legacy_system and temporary_compensating_control:
            return "Medium"
        if accepted_legacy_system:
            return "High"
        return "Critical"

    if status in {"extended-support", "limited-support"}:
        return "Medium"

    return "Low"
