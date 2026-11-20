"""Wire contracts aligned with the team's veilops/schema package (docs/CONTRACTS.md §6)."""
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

# Match veilops/schema/common.py: strict, immutable models and the same safe wire types.
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

EntityId = Annotated[str, StringConstraints(pattern=r"^(h|svc|lnk)_[0-9a-f]{10}$")]
PrincipalId = Annotated[str, StringConstraints(pattern=r"^usr_[0-9a-f]{10}$")]
SourceId = Annotated[str, StringConstraints(pattern=r"^src_[0-9a-f]{10}$")]
TenantId = Annotated[str, StringConstraints(pattern=r"^t_[a-z0-9_]{1,32}$")]
CollectorId = Annotated[str, StringConstraints(pattern=r"^col_[a-z0-9_]{1,32}$")]
Uuid = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
UuidV7 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
Sha256Hash = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
UtcTimestamp = Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")]
TimezoneName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+){0,2}$")]
SafeText = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:<>=%/ ,()\-]{1,160}$")]
Num = Annotated[float, Field(allow_inf_nan=False)]
ParamValue = Union[int, float]

Region = Literal["in", "eu"]
Severity = Literal["info", "warning", "high", "critical"]
HealthState = Literal["excellent", "good", "fair", "poor"]
EntityKind = Literal["host", "service", "link"]
MetricName = Literal[
    "cpu.util_pct", "mem.util_pct", "disk.util_pct", "disk.io_wait_pct",
    "svc.up", "svc.resp_ms", "net.latency_ms", "net.loss_pct",
    "net.bw_in_mbps", "net.bw_out_mbps", "net.reachable", "load.req_rate",
]

class PolicyRef(StrictModel):
    version: int = Field(ge=1)
    hash: Sha256Hash

class ChainRef(StrictModel):
    prev_hash: Sha256Hash
    payload_hash: Sha256Hash

class MetricRecord(StrictModel):
    type: Literal["metric"]
    entity: EntityId
    entity_kind: EntityKind
    metric: MetricName
    unit: Literal["pct", "ms", "mbps", "count", "bool", "rps"]
    avg: Num
    min: Num
    max: Num
    p95: Num
    count: int = Field(ge=1)
    window_s: int = Field(gt=0, le=3600)
    event_ts: UtcTimestamp
    source_tz: TimezoneName

class SecuritySummaryRecord(StrictModel):
    type: Literal["security_summary"]
    category: Literal[
        "auth.bruteforce", "auth.password_spray", "auth.spray",
        "auth.credential_stuffing", "auth.stuffing",
    ]
    severity: Severity
    count: int = Field(ge=0)
    distinct_principals: int = Field(ge=0)
    distinct_sources: int = Field(ge=0)
    principals: list[PrincipalId] = Field(max_length=20)
    sources: list[SourceId] = Field(max_length=20)
    risk_score: int = Field(ge=0, le=100)
    window_s: int = Field(gt=0, le=3600)
    event_ts: UtcTimestamp
    source_tz: TimezoneName

class AlertRecord(StrictModel):
    type: Literal["alert"]
    alert_id: Uuid
    entity: EntityId
    rule: str = Field(pattern=r"^[a-z0-9_.]{1,64}$")
    severity: Severity
    template_id: str = Field(pattern=r"^T_[A-Z0-9_]{1,48}$")
    params: dict[str, ParamValue] = Field(max_length=16)
    event_ts: UtcTimestamp
    source_tz: TimezoneName

class HealthRecord(StrictModel):
    type: Literal["health"]
    entity: EntityId
    state: HealthState
    reasons: list[SafeText] = Field(max_length=8)
    event_ts: UtcTimestamp

class TopologyEdge(StrictModel):
    src: EntityId
    dst: EntityId
    rel: Literal["runs_on", "depends_on", "routes_via", "connects_via"]

class TopologyRecord(StrictModel):
    type: Literal["topology"]
    edges: list[TopologyEdge] = Field(max_length=500)
    event_ts: UtcTimestamp

Record = Annotated[
    Union[MetricRecord, SecuritySummaryRecord, AlertRecord, HealthRecord, TopologyRecord],
    Field(discriminator="type"),
]

class Envelope(StrictModel):
    schema_version: str = Field(pattern=r"^\d{1,2}\.\d{1,2}$")
    payload_id: UuidV7
    tenant_id: TenantId
    collector_id: CollectorId
    region: Region
    seq: int = Field(ge=1)
    sent_at: UtcTimestamp
    policy: PolicyRef
    chain: ChainRef
    records: list[dict] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_and_normalize_records(self):
        allowed = {
            "metric": MetricRecord,
            "security_summary": SecuritySummaryRecord,
            "alert": AlertRecord,
            "health": HealthRecord,
            "topology": TopologyRecord,
        }
        normalized = []
        for item in self.records:
            kind = item.get("type") if isinstance(item, dict) else None
            model = allowed.get(kind)
            if model is None:
                raise ValueError(f"UNKNOWN_RECORD_TYPE: {kind!r}")
            normalized.append(model.model_validate(item).model_dump(mode="json"))
        object.__setattr__(self, "records", normalized)
        return self
