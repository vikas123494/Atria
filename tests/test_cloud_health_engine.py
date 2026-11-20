from datetime import datetime, timedelta, timezone

from cloud.app.health import (
    heartbeat_state, metric_state, combine_states, three_of_five_state,
)


def test_heartbeat_health_thresholds():
    now = datetime.now(timezone.utc)
    assert heartbeat_state(now, now)[0] == "Excellent"
    assert heartbeat_state(now - timedelta(seconds=15), now)[0] == "Fair"
    assert heartbeat_state(now - timedelta(seconds=30), now)[0] == "Fair"
    assert heartbeat_state(now - timedelta(seconds=31), now)[0] == "Poor"
    assert heartbeat_state(None, now)[0] == "Poor"


def test_metric_bands_and_state_combination():
    assert metric_state(40, 60, 80, 95) == "Excellent"
    assert metric_state(70, 60, 80, 95) == "Good"
    assert metric_state(85, 60, 80, 95) == "Fair"
    assert metric_state(98, 60, 80, 95) == "Poor"
    assert combine_states(["Good", "Poor", "Excellent"]) == "Poor"


def test_three_of_five_threshold():
    assert three_of_five_state(["Poor", "Poor", "Poor", "Good", "Good"]) == "Poor"
    assert three_of_five_state(["Fair", "Fair", "Good", "Fair", "Excellent"]) == "Fair"
    assert three_of_five_state(["Poor", "Fair", "Good", "Good", "Excellent"]) == "Excellent"
