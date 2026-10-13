from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EnvironmentalPriority:
    score: float
    band: str
    factors: dict
    rationale: str


def _band(score: float) -> str:
    if score >= 80:
        return "Urgent"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Minimal"


def calculate_environmental_priority(
    *,
    cvss_base_score: float,
    asset_criticality: int,
    exposure: int,
    exploit_maturity: int,
    kev: bool,
    epss: float | None,
) -> EnvironmentalPriority:
    """
    VulnForge environmental priority is deliberately separate from CVSS.

    Weighted score:
      CVSS base severity         30%
      asset criticality         25%
      exposure                  15%
      exploit maturity          10%
      CISA KEV                  10%
      EPSS                      10%

    This is a local prioritisation model, not a CVSS score and not a replacement
    for the CVSS Environmental metric group.
    """
    cvss_component = max(0.0, min(100.0, cvss_base_score * 10.0))
    epss_component = 0.0 if epss is None else max(0.0, min(100.0, epss * 100.0))
    kev_component = 100.0 if kev else 0.0

    score = (
        cvss_component * 0.30
        + asset_criticality * 0.25
        + exposure * 0.15
        + exploit_maturity * 0.10
        + kev_component * 0.10
        + epss_component * 0.10
    )
    score = round(score, 2)

    factors = {
        "cvss_component": round(cvss_component, 2),
        "asset_criticality": asset_criticality,
        "exposure": exposure,
        "exploit_maturity": exploit_maturity,
        "kev": kev,
        "epss": epss,
        "weights": {
            "cvss": 0.30,
            "asset_criticality": 0.25,
            "exposure": 0.15,
            "exploit_maturity": 0.10,
            "kev": 0.10,
            "epss": 0.10,
        },
    }

    rationale = (
        f"CVSS contributes 30% of the VulnForge environmental priority. "
        f"Asset criticality={asset_criticality}, exposure={exposure}, "
        f"exploit maturity={exploit_maturity}, KEV={kev}, EPSS={epss}. "
        "Therefore identical CVSS scores can produce different priorities in different environments."
    )

    return EnvironmentalPriority(
        score=score,
        band=_band(score),
        factors=factors,
        rationale=rationale,
    )
