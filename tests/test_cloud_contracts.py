from pydantic import ValidationError
import pytest

from cloud.app.contracts import Envelope


def valid_envelope():
    return {
        "schema_version": "1.0",
        "payload_id": "0193b7c2-5e1a-7c3d-9f00-1a2b3c4d5e6f",
        "tenant_id": "t_acme",
        "collector_id": "col_blr_01",
        "region": "in",
        "seq": 1042,
        "sent_at": "2026-11-21T04:12:07.530Z",
        "policy": {"version": 3, "hash": "sha256:" + "a" * 64},
        "chain": {"prev_hash": "sha256:" + "b" * 64, "payload_hash": "sha256:" + "c" * 64},
        "records": [{
            "type": "metric", "entity": "h_7f3a21c90b", "entity_kind": "host",
            "metric": "cpu.util_pct", "unit": "pct", "avg": 91.2,
            "min": 88.0, "max": 94.1, "p95": 93.8, "count": 5,
            "window_s": 5, "event_ts": "2026-11-21T04:12:00.000Z",
            "source_tz": "Asia/Kolkata"
        }]
    }


def test_valid_metric_envelope_is_accepted():
    envelope = Envelope.model_validate(valid_envelope())
    assert envelope.seq == 1042
    assert envelope.records[0]["type"] == "metric"


def test_unknown_record_type_is_rejected():
    data = valid_envelope()
    data["records"] = [{"type": "raw_log", "message": "must not be accepted"}]
    with pytest.raises(ValidationError, match="UNKNOWN_RECORD_TYPE"):
        Envelope.model_validate(data)


def test_free_text_is_not_allowed_in_metric_record():
    data = valid_envelope()
    data["records"][0]["message"] = "unexpected free text"
    with pytest.raises(ValidationError):
        Envelope.model_validate(data)


def test_payload_id_must_be_uuid7():
    data = valid_envelope()
    data["payload_id"] = "0193b7c2-5e1a-1c3d-9f00-1a2b3c4d5e6f"
    with pytest.raises(ValidationError):
        Envelope.model_validate(data)
