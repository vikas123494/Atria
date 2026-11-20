from datetime import datetime, timedelta, timezone

from cloud.app.health import (
    cap_for_stale_metrics,
    heartbeat_state,
    metric_state,
    recovered_inside_margin,
    three_of_five_state,
    DEFAULT_THRESHOLDS,
)


def test_heartbeat_age_bands_match_architecture():
    now = datetime.now(timezone.utc)
    assert heartbeat_state(now - timedelta(seconds=9), now)[0] == "Excellent"
    assert heartbeat_state(now - timedelta(seconds=10), now)[0] == "Good"
    assert heartbeat_state(now - timedelta(seconds=14), now)[0] == "Good"
    assert heartbeat_state(now - timedelta(seconds=15), now)[0] == "Fair"
    assert heartbeat_state(now - timedelta(seconds=30), now)[0] == "Fair"
    assert heartbeat_state(now - timedelta(seconds=31), now)[0] == "Poor"


def test_three_of_five_requires_repeated_state():
    assert three_of_five_state(["Fair", "Fair", "Good", "Fair", "Excellent"]) == "Fair"
    assert three_of_five_state(["Poor", "Fair", "Good", "Excellent", "Excellent"]) == "Excellent"


def test_architecture_default_thresholds():
    assert DEFAULT_THRESHOLDS["cpu.util_pct"] == (60.0, 75.0, 90.0)
    assert DEFAULT_THRESHOLDS["mem.util_pct"] == (70.0, 80.0, 92.0)
    assert DEFAULT_THRESHOLDS["disk.util_pct"] == (70.0, 85.0, 95.0)
    assert DEFAULT_THRESHOLDS["net.loss_pct"] == (0.5, 2.0, 5.0)


def test_metric_threshold_bands():
    assert metric_state(50, 60, 75, 90) == "Excellent"
    assert metric_state(65, 60, 75, 90) == "Good"
    assert metric_state(80, 60, 75, 90) == "Fair"
    assert metric_state(95, 60, 75, 90) == "Poor"


def test_recovery_requires_three_samples_inside_configured_margin():
    assert recovered_inside_margin([65, 66, 67], "Good", 60, 75, 90, 0.10)
    assert not recovered_inside_margin([70, 66, 67], "Good", 60, 75, 90, 0.10)
    assert not recovered_inside_margin([65, 66], "Good", 60, 75, 90, 0.10)


def test_stale_metric_data_caps_health():
    now = datetime.now(timezone.utc)
    assert cap_for_stale_metrics("Excellent", now - timedelta(seconds=20), now)[0] == "Good"
    assert cap_for_stale_metrics("Excellent", now - timedelta(seconds=31), now)[0] == "Fair"
    assert cap_for_stale_metrics("Poor", now - timedelta(seconds=31), now)[0] == "Poor"
