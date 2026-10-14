from app.schemas.environmental_risk import (
    FACTOR_NAMES,
    RiskScoreVersionCreate,
)
from app.services.environmental_risk_defaults import DEFAULT_WEIGHTS


def test_default_weights_cover_every_factor():
    assert set(DEFAULT_WEIGHTS) == set(FACTOR_NAMES)
    assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 0.001


def test_custom_score_version_accepts_configurable_weights():
    model = RiskScoreVersionCreate(
        version_key="experiment-17b",
        name="Experiment 17B",
        description="Alternative weighting experiment.",
        experimental=True,
        active=True,
        weights=DEFAULT_WEIGHTS,
        interaction_rules={
            "exposed_kev_critical_path_bonus": 10.0,
        },
    )
    assert model.version_key == "experiment-17b"
    assert model.experimental is True
