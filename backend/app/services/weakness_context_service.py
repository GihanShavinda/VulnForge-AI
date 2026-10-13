from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_intel import ThreatIntelObservation, ThreatIntelSource
from app.models.weakness_context import AttackTechnique, BehaviourObservation, WeaknessCapecMapping, WeaknessTechniqueMapping
from app.services.weakness_attack_catalog import (
    ATTACK_TECHNIQUES,
    CWE_CAPEC_MAPPINGS,
    POTENTIAL_TECHNIQUE_MAPPINGS,
    get_attack_technique,
    get_capec_for_cwe,
    get_potential_techniques,
)


DISCLAIMER = (
    "ATT&CK technique mappings describe possible attacker behaviour only. "
    "The presence of a vulnerability or weakness does not prove that an ATT&CK technique occurred. "
    "Observed and confirmed behaviour require explicit evidence."
)


def ensure_attack_catalog(db: Session) -> None:
    changed = False

    for attack_id, item in ATTACK_TECHNIQUES.items():
        row = db.scalar(select(AttackTechnique).where(AttackTechnique.attack_id == attack_id))
        if row is None:
            db.add(
                AttackTechnique(
                    attack_id=attack_id,
                    name=item["name"],
                    tactic=item["tactic"],
                    subtechnique_of=item["subtechnique_of"],
                    source=item["source"],
                    source_url=item["source_url"],
                )
            )
            changed = True

    for cwe_id, mappings in CWE_CAPEC_MAPPINGS.items():
        for item in mappings:
            row = db.scalar(
                select(WeaknessCapecMapping).where(
                    WeaknessCapecMapping.cwe_id == cwe_id,
                    WeaknessCapecMapping.capec_id == item["capec_id"],
                )
            )
            if row is None:
                db.add(
                    WeaknessCapecMapping(
                        cwe_id=cwe_id,
                        capec_id=item["capec_id"],
                        capec_name=item["capec_name"],
                        mapping_confidence=item["mapping_confidence"],
                        mapping_source=item["mapping_source"],
                        mapping_rationale=item["mapping_rationale"],
                        source_url=item["source_url"],
                    )
                )
                changed = True

    for (subject_type, subject_id), mappings in POTENTIAL_TECHNIQUE_MAPPINGS.items():
        for item in mappings:
            row = db.scalar(
                select(WeaknessTechniqueMapping).where(
                    WeaknessTechniqueMapping.subject_type == subject_type,
                    WeaknessTechniqueMapping.subject_id == subject_id,
                    WeaknessTechniqueMapping.attack_id == item["attack_id"],
                )
            )
            if row is None:
                db.add(
                    WeaknessTechniqueMapping(
                        subject_type=subject_type,
                        subject_id=subject_id,
                        attack_id=item["attack_id"],
                        context_type="potential",
                        mapping_confidence=item["mapping_confidence"],
                        mapping_source=item["mapping_source"],
                        mapping_rationale=item["mapping_rationale"],
                    )
                )
                changed = True

    if changed:
        db.commit()


def _technique_context(attack_id: str, context_type: str, confidence: str, source: str, rationale: str) -> dict | None:
    technique = get_attack_technique(attack_id)
    if technique is None:
        return None
    return {
        "attack_id": attack_id,
        "name": technique["name"],
        "tactic": technique["tactic"],
        "subtechnique_of": technique["subtechnique_of"],
        "context_type": context_type,
        "mapping_confidence": confidence,
        "mapping_source": source,
        "mapping_rationale": rationale,
    }


def build_vulnerability_context(db: Session, canonical_id: str) -> dict:
    rows = db.execute(
        select(ThreatIntelObservation, ThreatIntelSource.name)
        .join(ThreatIntelSource, ThreatIntelObservation.source_id == ThreatIntelSource.id)
        .where(ThreatIntelObservation.canonical_id == canonical_id)
        .order_by(ThreatIntelObservation.observed_at.desc())
    ).all()

    source_by_cwe: dict[str, set[str]] = {}
    for observation, source_name in rows:
        for cwe in observation.cwes or []:
            normalized = str(cwe).upper()
            if normalized.startswith("CWE-"):
                source_by_cwe.setdefault(normalized, set()).add(source_name)

    weaknesses = []
    possible = []
    seen_possible = set()

    for cwe_id in sorted(source_by_cwe):
        capec_rows = get_capec_for_cwe(cwe_id)
        weaknesses.append(
            {
                "cwe_id": cwe_id,
                "intelligence_sources": sorted(source_by_cwe[cwe_id]),
                "capec": capec_rows,
            }
        )

        for mapping in get_potential_techniques("cwe", cwe_id):
            key = (mapping["attack_id"], mapping["mapping_rationale"])
            if key not in seen_possible:
                item = _technique_context(
                    mapping["attack_id"],
                    "potential",
                    mapping["mapping_confidence"],
                    mapping["mapping_source"],
                    mapping["mapping_rationale"],
                )
                if item:
                    possible.append(item)
                    seen_possible.add(key)

        for capec in capec_rows:
            for mapping in get_potential_techniques("capec", capec["capec_id"]):
                key = (mapping["attack_id"], mapping["mapping_rationale"])
                if key not in seen_possible:
                    item = _technique_context(
                        mapping["attack_id"],
                        "potential",
                        mapping["mapping_confidence"],
                        mapping["mapping_source"],
                        mapping["mapping_rationale"],
                    )
                    if item:
                        possible.append(item)
                        seen_possible.add(key)

    behaviour_rows = list(
        db.scalars(
            select(BehaviourObservation)
            .where(BehaviourObservation.canonical_id == canonical_id)
            .order_by(BehaviourObservation.created_at.asc())
        ).all()
    )

    observed = []
    for row in behaviour_rows:
        item = _technique_context(
            row.attack_id,
            row.context_type,
            row.mapping_confidence,
            row.mapping_source,
            row.mapping_rationale,
        )
        if item:
            observed.append(item)

    return {
        "canonical_id": canonical_id,
        "security_weaknesses": weaknesses,
        "possible_attacker_behaviour": possible,
        "observed_or_confirmed_behaviour": observed,
        "disclaimer": DISCLAIMER,
    }


def build_finding_context(db: Session, finding_id: str) -> dict:
    potential_rows = list(
        db.scalars(
            select(WeaknessTechniqueMapping)
            .where(
                WeaknessTechniqueMapping.subject_type == "finding",
                WeaknessTechniqueMapping.subject_id == finding_id,
                WeaknessTechniqueMapping.context_type == "potential",
            )
            .order_by(WeaknessTechniqueMapping.created_at.asc())
        ).all()
    )

    possible = []
    for row in potential_rows:
        item = _technique_context(
            row.attack_id,
            "potential",
            row.mapping_confidence,
            row.mapping_source,
            row.mapping_rationale,
        )
        if item:
            possible.append(item)

    behaviour_rows = list(
        db.scalars(
            select(BehaviourObservation)
            .where(BehaviourObservation.finding_id == finding_id)
            .order_by(BehaviourObservation.created_at.asc())
        ).all()
    )
    observed = []
    for row in behaviour_rows:
        item = _technique_context(
            row.attack_id,
            row.context_type,
            row.mapping_confidence,
            row.mapping_source,
            row.mapping_rationale,
        )
        if item:
            observed.append(item)

    return {
        "finding_id": finding_id,
        "possible_attacker_behaviour": possible,
        "observed_or_confirmed_behaviour": observed,
        "disclaimer": DISCLAIMER,
    }
