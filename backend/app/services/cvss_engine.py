from __future__ import annotations

from dataclasses import dataclass

from cvss import CVSS3, CVSS4


V31_LABELS = {
    "AV": "attack_vector",
    "AC": "attack_complexity",
    "PR": "privileges_required",
    "UI": "user_interaction",
    "S": "scope",
    "C": "confidentiality_impact",
    "I": "integrity_impact",
    "A": "availability_impact",
    "E": "exploit_code_maturity",
    "RL": "remediation_level",
    "RC": "report_confidence",
    "CR": "confidentiality_requirement",
    "IR": "integrity_requirement",
    "AR": "availability_requirement",
    "MAV": "modified_attack_vector",
    "MAC": "modified_attack_complexity",
    "MPR": "modified_privileges_required",
    "MUI": "modified_user_interaction",
    "MS": "modified_scope",
    "MC": "modified_confidentiality_impact",
    "MI": "modified_integrity_impact",
    "MA": "modified_availability_impact",
}

V4_LABELS = {
    "AV": "attack_vector",
    "AC": "attack_complexity",
    "AT": "attack_requirements",
    "PR": "privileges_required",
    "UI": "user_interaction",
    "VC": "vulnerable_system_confidentiality",
    "VI": "vulnerable_system_integrity",
    "VA": "vulnerable_system_availability",
    "SC": "subsequent_system_confidentiality",
    "SI": "subsequent_system_integrity",
    "SA": "subsequent_system_availability",
    "E": "threat_exploit_maturity",
    "CR": "confidentiality_requirement",
    "IR": "integrity_requirement",
    "AR": "availability_requirement",
    "MAV": "modified_attack_vector",
    "MAC": "modified_attack_complexity",
    "MAT": "modified_attack_requirements",
    "MPR": "modified_privileges_required",
    "MUI": "modified_user_interaction",
    "MVC": "modified_vulnerable_system_confidentiality",
    "MVI": "modified_vulnerable_system_integrity",
    "MVA": "modified_vulnerable_system_availability",
    "MSC": "modified_subsequent_system_confidentiality",
    "MSI": "modified_subsequent_system_integrity",
    "MSA": "modified_subsequent_system_availability",
    "S": "safety",
    "AU": "automatable",
    "R": "recovery",
    "V": "value_density",
    "RE": "response_effort",
    "U": "provider_urgency",
}

VALUE_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "AT": {"N": "None", "P": "Present"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "P": "Passive", "A": "Active", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed", "N": "Negligible", "P": "Present"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"},
    "VC": {"N": "None", "L": "Low", "H": "High"},
    "VI": {"N": "None", "L": "Low", "H": "High"},
    "VA": {"N": "None", "L": "Low", "H": "High"},
    "SC": {"N": "Negligible", "L": "Low", "H": "High"},
    "SI": {"N": "Negligible", "L": "Low", "H": "High", "S": "Safety"},
    "SA": {"N": "Negligible", "L": "Low", "H": "High", "S": "Safety"},
    "E": {"X": "Not Defined", "A": "Attacked", "P": "Proof-of-Concept", "U": "Unreported", "H": "High", "F": "Functional"},
    "CR": {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
    "IR": {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
    "AR": {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
}


@dataclass(frozen=True)
class ParsedCVSS:
    version: str
    original_vector: str
    base_score: float
    severity: str
    components: dict


def severity_from_score(score: float) -> str:
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def _parse_tokens(vector: str, version: str) -> dict[str, str]:
    expected = "CVSS:3.1/" if version == "3.1" else "CVSS:4.0/"
    if not vector.startswith(expected):
        raise ValueError(f"Vector does not match CVSS {version}; version conversion is not performed.")

    raw: dict[str, str] = {}
    for token in vector[len(expected):].split("/"):
        if not token or ":" not in token:
            raise ValueError(f"Invalid CVSS metric token: {token!r}")
        key, value = token.split(":", 1)
        if not key or not value:
            raise ValueError(f"Invalid CVSS metric token: {token!r}")
        if key in raw:
            raise ValueError(f"Duplicate CVSS metric: {key}")
        raw[key] = value
    return raw


def _component_view(raw: dict[str, str], labels: dict[str, str]) -> dict:
    parsed = {}
    for metric, value in raw.items():
        parsed[labels.get(metric, metric.lower())] = {
            "metric": metric,
            "value": value,
            "label": VALUE_LABELS.get(metric, {}).get(value, value),
        }
    return parsed


def parse_cvss(vector: str) -> ParsedCVSS:
    vector = vector.strip()

    if vector.startswith("CVSS:3.1/"):
        raw = _parse_tokens(vector, "3.1")
        try:
            score = float(CVSS3(vector).scores()[0])
        except Exception as exc:
            raise ValueError(f"Invalid CVSS v3.1 vector: {exc}") from exc
        return ParsedCVSS(
            version="3.1",
            original_vector=vector,
            base_score=score,
            severity=severity_from_score(score),
            components=_component_view(raw, V31_LABELS),
        )

    if vector.startswith("CVSS:4.0/"):
        raw = _parse_tokens(vector, "4.0")
        try:
            score = float(CVSS4(vector).scores()[0])
        except Exception as exc:
            raise ValueError(f"Invalid CVSS v4.0 vector: {exc}") from exc
        return ParsedCVSS(
            version="4.0",
            original_vector=vector,
            base_score=score,
            severity=severity_from_score(score),
            components=_component_view(raw, V4_LABELS),
        )

    if vector.startswith("CVSS:"):
        raise ValueError("Only CVSS v3.1 and CVSS v4.0 are supported. VulnForge does not silently convert CVSS versions.")

    raise ValueError("Vector must start with CVSS:3.1/ or CVSS:4.0/")
