from datetime import datetime, timedelta, timezone

from cloud.app.processor import calculate_event_time_watermark


def test_event_inside_five_minute_lateness_is_not_late():
    now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    maximum, watermark, late = calculate_event_time_watermark(now, now - timedelta(minutes=4))
    assert maximum == now
    assert watermark == now - timedelta(minutes=5)
    assert late is False


def test_event_older_than_watermark_is_retained_as_late():
    now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    maximum, watermark, late = calculate_event_time_watermark(now, now - timedelta(minutes=6))
    assert maximum == now
    assert watermark == now - timedelta(minutes=5)
    assert late is True


def test_new_event_advances_watermark_without_moving_it_backwards():
    previous = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    incoming = previous + timedelta(minutes=2)
    maximum, watermark, late = calculate_event_time_watermark(previous, incoming)
    assert maximum == incoming
    assert watermark == incoming - timedelta(minutes=5)
    assert late is False
