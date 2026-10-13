from app.services.environmental_priority import calculate_environmental_priority


def test_identical_cvss_can_have_different_environmental_priorities():
    low_context = calculate_environmental_priority(
        cvss_base_score=9.8,
        asset_criticality=20,
        exposure=10,
        exploit_maturity=10,
        kev=False,
        epss=0.05,
    )
    high_context = calculate_environmental_priority(
        cvss_base_score=9.8,
        asset_criticality=100,
        exposure=100,
        exploit_maturity=100,
        kev=True,
        epss=0.99,
    )

    assert low_context.score != high_context.score
    assert high_context.score > low_context.score


def test_cvss_is_not_entire_priority():
    priority = calculate_environmental_priority(
        cvss_base_score=10.0,
        asset_criticality=0,
        exposure=0,
        exploit_maturity=0,
        kev=False,
        epss=0.0,
    )
    assert priority.score == 30.0
