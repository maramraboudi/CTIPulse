from app.scoring import calculate_risk, priority_for


def test_calculate_risk_maximum() -> None:
    assert calculate_risk(10, 1, True, 1) == 100.0


def test_calculate_risk_no_signals() -> None:
    assert calculate_risk(0, 0, False, 0) == 0.0


def test_weighted_example() -> None:
    score = calculate_risk(9.8, 0.90, True, 1)
    assert score == 96.0


def test_priority_thresholds() -> None:
    assert priority_for(80) == "Critical"
    assert priority_for(60) == "High"
    assert priority_for(40) == "Medium"
    assert priority_for(39.9) == "Low"
