"""Versioned collector-to-cloud contracts (Architecture §12)."""
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class PolicyRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=1)
    hash: str = Field(pattern=r"^sha256:[0-9a-fA-F]{64}$")


class ChainRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prev_hash: str = Field(pattern=r"^sha256:[0-9a-fA-F]{64}$")
    payload_hash: str = Field(pattern=r"^sha256:[0-9a-fA-F]{64}$")


class MetricRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["metric"]
    entity: str = Field(min_length=1, max_length=128)
    entity_kind: str = Field(min_length=1, max_length=32)
    metric: str = Field(min_length=1, max_length=128)
    unit: str = Field(min_length=1, max_length=32)
    avg: float | None = None
    min: float | None = None
    max: float | None = None
    p95: float | None = None
    count: int = Field(ge=0)
    window_s: int = Field(gt=0)
    event_ts: datetime
    source_tz: str = Field(min_length=1, max_length=64)


class SecuritySummaryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["security_summary"]
    category: str = Field(min_length=1, max_length=128)
    severity: Literal["info", "low", "medium", "high", "critical"]
    count: int = Field(ge=0)
    distinct_principals: int = Field(ge=0)
    distinct_sources: int = Field(ge=0)
    principals: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    risk_score: int = Field(ge=0, le=100)
    window_s: int = Field(gt=0)
    event_ts: datetime
    source_tz: str = Field(min_length=1, max_length=64)


class AlertRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["alert"]
    alert_id: UUID
    entity: str = Field(min_length=1, max_length=128)
    rule: str = Field(min_length=1, max_length=128)
    severity: Literal["info", "warning", "critical"]
    template_id: str = Field(min_length=1, max_length=64)
    params: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    event_ts: datetime
    source_tz: str = Field(min_length=1, max_length=64)


class HealthRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["health"]
    entity: str = Field(min_length=1, max_length=128)
    state: Literal["Excellent", "Good", "Fair", "Poor"]
    score: float | None = Field(default=None, ge=0, le=100)
    reasons: list[str] = Field(default_factory=list, max_length=32)
    event_ts: datetime
    source_tz: str = Field(min_length=1, max_length=64)


Record = MetricRecord | SecuritySummaryRecord | AlertRecord | HealthRecord


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    payload_id: UUID
    tenant_id: str = Field(min_length=1, max_length=128)
    collector_id: str = Field(min_length=1, max_length=128)
    region: Literal["in", "eu"]
    seq: int = Field(ge=1)
    sent_at: datetime
    policy: PolicyRef
    chain: ChainRef
    records: list[dict[str, Any]] = Field(min_length=1, max_length=5000)

    @field_validator("payload_id")
    @classmethod
    def require_uuid7(cls, value: UUID) -> UUID:
        if value.version != 7:
            raise ValueError("payload_id must be UUIDv7")
        return value

    @field_validator("sent_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("sent_at must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_records(self):
        allowed = {
            "metric": MetricRecord,
            "security_summary": SecuritySummaryRecord,
            "alert": AlertRecord,
            "health": HealthRecord,
        }
        parsed = []
        for item in self.records:
            kind = item.get("type") if isinstance(item, dict) else None
            model = allowed.get(kind)
            if model is None:
                raise ValueError(f"UNKNOWN_RECORD_TYPE: {kind!r}")
            parsed.append(model.model_validate(item))
        self.records = [item.model_dump(mode="json") for item in parsed]
        return self
