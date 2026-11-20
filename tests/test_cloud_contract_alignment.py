from pydantic import ValidationError
import pytest

from cloud.app.contracts import Envelope


BASE = {
    "schema_version": "1.0",
    "payload_id": "018f47a2-8c10-7abc-8def-1234567890ab",
    "tenant_id": "t_acme",
    "collector_id": "col_blr_01",
    "region": "in",
    "seq": 1,
    "sent_at": "2026-11-20T12:00:00.000Z",
    "policy": {"version": 1, "hash": "sha256:" + "a" * 64},
    "chain": {"prev_hash": "sha256:" + "0" * 64, "payload_hash": "sha256:" + "b" * 64},
}


def envelope_with(record):
    return {**BASE, "records": [record]}


def test_team_metric_record_validates_without_coercion():
    record = {
        "type": "metric", "entity": "h_0123456789", "entity_kind": "host",
        "metric": "cpu.util_pct", "unit": "pct", "avg": 42.5, "min": 40.0,
        "max": 45.0, "p95": 44.0, "count": 5, "window_s": 5,
        "event_ts": "2026-11-20T12:00:00.000Z", "source_tz": "Asia/Kolkata",
    }
    parsed = Envelope.model_validate(envelope_with(record))
    assert parsed.records[0]["metric"] == "cpu.util_pct"


def test_team_alert_accepts_high_severity_and_numeric_params():
    record = {
        "type": "alert", "alert_id": "018f47a2-8c10-7abc-8def-1234567890ac",
        "entity": "h_0123456789", "rule": "threshold.disk.high",
        "severity": "high", "template_id": "T_DISK_HIGH",
        "params": {"value": 96.0, "threshold": 90, "breaching": 3, "of": 5},
        "event_ts": "2026-11-20T12:00:00.000Z", "source_tz": "Asia/Kolkata",
    }
    assert Envelope.model_validate(envelope_with(record)).records[0]["severity"] == "high"


def test_team_health_record_uses_lowercase_state_and_no_extra_fields():
    record = {
        "type": "health", "entity": "svc_0123456789", "state": "poor",
        "reasons": ["service_unreachable"], "event_ts": "2026-11-20T12:00:00.000Z",
    }
    assert Envelope.model_validate(envelope_with(record)).records[0]["state"] == "poor"
    record["state"] = "Poor"
    with pytest.raises(ValidationError):
        Envelope.model_validate(envelope_with(record))


def test_team_topology_record_is_accepted():
    record = {
        "type": "topology",
        "edges": [{"src": "svc_0123456789", "dst": "h_0123456789", "rel": "runs_on"}],
        "event_ts": "2026-11-20T12:00:00.000Z",
    }
    parsed = Envelope.model_validate(envelope_with(record))
    assert parsed.records[0]["edges"][0]["rel"] == "runs_on"


def test_unknown_record_and_non_pseudonymous_entity_are_rejected():
    with pytest.raises(ValidationError):
        Envelope.model_validate(envelope_with({"type": "unknown", "event_ts": "2026-11-20T12:00:00.000Z"}))
    record = {
        "type": "health", "entity": "app-01", "state": "poor",
        "reasons": [], "event_ts": "2026-11-20T12:00:00.000Z",
    }
    with pytest.raises(ValidationError):
        Envelope.model_validate(envelope_with(record))
