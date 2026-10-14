from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.environmental_risk import (
    EnvironmentalRiskContribution,
    EnvironmentalRiskScore,
    RiskScoreVersion,
)
from app.models.security_lab import Asset
from app.services.environmental_risk_defaults import (
    DEFAULT_DESCRIPTION,
    DEFAULT_INTERACTION_RULES,
    DEFAULT_VERSION_KEY,
    DEFAULT_WEIGHTS,
)
from app.services.environmental_risk_engine import calculate_environmental_risk


def ensure_default_version(db: Session) -> RiskScoreVersion:
    existing = db.scalar(
        select(RiskScoreVersion).where(
            RiskScoreVersion.version_key == DEFAULT_VERSION_KEY
        )
    )
    if existing is not None:
        return existing

    version = RiskScoreVersion(
        version_key=DEFAULT_VERSION_KEY,
        name="Environmental Risk Score 2.0",
        description=DEFAULT_DESCRIPTION,
        experimental=True,
        active=True,
        weights=DEFAULT_WEIGHTS,
        interaction_rules=DEFAULT_INTERACTION_RULES,
    )
    db.add(version)
    db.commit()
    db.refresh(version)
    return version


def create_score_version(
    db: Session,
    *,
    version_key: str,
    name: str,
    description: str,
    experimental: bool,
    active: bool,
    weights: dict,
    interaction_rules: dict,
):
    if db.scalar(
        select(RiskScoreVersion).where(
            RiskScoreVersion.version_key == version_key
        )
    ):
        raise ValueError("Score version already exists.")

    row = RiskScoreVersion(
        version_key=version_key,
        name=name,
        description=description,
        experimental=experimental,
        active=active,
        weights=weights,
        interaction_rules=interaction_rules,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_score_versions(db: Session):
    ensure_default_version(db)
    return list(
        db.scalars(
            select(RiskScoreVersion)
            .order_by(RiskScoreVersion.created_at.desc())
        ).all()
    )


def calculate_and_store(
    db: Session,
    *,
    asset_id,
    vulnerability_id: str | None,
    calculation_version: str,
    factors: dict,
):
    if asset_id is not None and db.get(Asset, asset_id) is None:
        raise ValueError("Asset not found.")

    version = db.scalar(
        select(RiskScoreVersion).where(
            RiskScoreVersion.version_key == calculation_version
        )
    )
    if version is None:
        if calculation_version == DEFAULT_VERSION_KEY:
            version = ensure_default_version(db)
        else:
            raise ValueError("Risk score version not found.")

    if not version.active:
        raise ValueError("Risk score version is inactive.")

    calculation = calculate_environmental_risk(
        factors,
        version.weights,
        version.interaction_rules,
    )

    score = EnvironmentalRiskScore(
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        score_version_id=version.id,
        calculation_version=version.version_key,
        raw_factors=calculation.raw_factors,
        normalized_factors=calculation.normalized_factors,
        weights=calculation.weights,
        base_score=calculation.base_score,
        interaction_adjustment=calculation.interaction_adjustment,
        final_score=calculation.final_score,
        priority_tier=calculation.priority_tier,
        experimental=version.experimental,
        rationale=calculation.rationale,
    )
    db.add(score)
    db.flush()

    rows: list[EnvironmentalRiskContribution] = []
    for item in calculation.contributions:
        raw_value = (
            json.dumps(item.raw_value, sort_keys=True)
            if isinstance(item.raw_value, (dict, list))
            else str(item.raw_value)
        )
        row = EnvironmentalRiskContribution(
            score_id=score.id,
            factor_name=item.factor_name,
            contribution_type=item.contribution_type,
            raw_value=raw_value,
            normalized_value=item.normalized_value,
            configured_weight=item.configured_weight,
            contribution=item.contribution,
            reason=item.reason,
            sequence=item.sequence,
        )
        db.add(row)
        rows.append(row)

    db.commit()
    db.refresh(score)
    for row in rows:
        db.refresh(row)

    return score, rows


def list_scores(db: Session):
    return list(
        db.scalars(
            select(EnvironmentalRiskScore)
            .order_by(EnvironmentalRiskScore.created_at.desc())
        ).all()
    )


def get_score(db: Session, score_id):
    return db.get(EnvironmentalRiskScore, score_id)


def list_contributions(db: Session, score_id):
    return list(
        db.scalars(
            select(EnvironmentalRiskContribution)
            .where(EnvironmentalRiskContribution.score_id == score_id)
            .order_by(EnvironmentalRiskContribution.sequence.asc())
        ).all()
    )
