from datetime import datetime, timedelta, timezone

from cloud.app.health import (
    cap_for_stale_metrics,
    heartbeat_state,
    metric_state,
    recovered_inside_margin,
    three_of_five_state,
)


def test_heartbeat_age_bands():
    now = datetime.now(timezone.utc)
    assert heartbeat_state(now - timedelta(seconds=14), now)[0] == "Good"
    assert heartbeat_state(now - timedelta(seconds=15), now)[0] == "Fair"
    assert heartbeat_state(now - timedelta(seconds=30), now)[0] == "Poor"


def test_three_of_five_requires_repeated_state():
    assert three_of_five_state(["Fair", "Fair", "Good", "Fair", "Excellent"]) == "Fair"
    assert three_of_five_state(["Poor", "Fair", "Good", "Excellent", "Excellent"]) == "Excellent"


def test_metric_threshold_bands():
    assert metric_state(50, 60, 75, 90) == "Excellent"
    assert metric_state(65, 60, 75, 90) == "Good"
    assert metric_state(80, 60, 75, 90) == "Fair"
    assert metric_state(95, 60, 75, 90) == "Poor"


def test_recovery_requires_three_samples_inside_ten_percent_margin():
    assert recovered_inside_margin([65, 66, 67], "Good", 60, 75, 90)
    assert not recovered_inside_margin([70, 66, 67], "Good", 60, 75, 90)
    assert not recovered_inside_margin([65, 66], "Good", 60, 75, 90)


def test_stale_metric_data_caps_health():
    now = datetime.now(timezone.utc)
    assert cap_for_stale_metrics("Excellent", now - timedelta(seconds=20), now)[0] == "Good"
    assert cap_for_stale_metrics("Excellent", now - timedelta(seconds=31), now)[0] == "Fair"
    assert cap_for_stale_metrics("Poor", now - timedelta(seconds=31), now)[0] == "Poor"
