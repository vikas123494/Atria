"""Tenant-scoped dashboard and operational APIs (Person C backend scope)."""
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(prefix="/api/v1", tags=["dashboard-api"])


def tenant_from_request(request: Request) -> str:
    # Authentication middleware must populate this from a verified JWT claim.
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(401, detail={"code": "UNAUTHENTICATED"})
    return tenant_id


async def require_role(request: Request, allowed: set[str]) -> str:
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        role = await conn.fetchval(
            "SELECT role FROM memberships WHERE user_id=$1 AND tenant_id=$2",
            str(request.state.user_id), tenant,
        )
    if role is None:
        raise HTTPException(403, detail={"code": "TENANT_MEMBERSHIP_REQUIRED"})
    if role not in allowed:
        raise HTTPException(403, detail={"code": "INSUFFICIENT_ROLE", "required": sorted(allowed)})
    request.state.tenant_role = role
    return tenant


@router.get("/fleet")
async def fleet(request: Request):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT c.collector_id,c.region,c.status,
                          max(h.ts) AS last_heartbeat,
                          count(DISTINCT e.entity) AS entity_count
                   FROM collectors c
                   LEFT JOIN collector_heartbeats h
                     ON h.tenant_id=c.tenant_id AND h.collector_id=c.collector_id
                   LEFT JOIN entities e
                     ON e.tenant_id=c.tenant_id AND e.collector_id=c.collector_id
                   WHERE c.tenant_id=$1 AND c.revoked_at IS NULL
                   GROUP BY c.collector_id,c.region,c.status ORDER BY c.collector_id""",
                tenant,
            )
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            entity_rows = await conn.fetch(
                """SELECT e.entity,e.kind,e.environment,e.collector_id,
                          h.state,h.reasons,h.since,h.last_data_ts
                   FROM entities e LEFT JOIN health_current h
                     ON h.tenant_id=e.tenant_id AND h.entity=e.entity
                   WHERE e.tenant_id=$1 ORDER BY e.environment,e.entity""",
                tenant,
            )
    return {
        "tenant_id": tenant,
        "collectors": [dict(r) for r in rows],
        "entities": [dict(r) for r in entity_rows],
    }


@router.get("/collectors/{collector_id}")
async def collector_detail(collector_id: str, request: Request):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            row = await conn.fetchrow(
                """SELECT collector_id,region,status,enrolled_at,revoked_at
                   FROM collectors WHERE tenant_id=$1 AND collector_id=$2""",
                tenant, collector_id,
            )
            if not row:
                raise HTTPException(404, detail={"code": "COLLECTOR_NOT_FOUND"})
            hb = await conn.fetchrow(
                """SELECT ts,body FROM collector_heartbeats
                   WHERE tenant_id=$1 AND collector_id=$2 ORDER BY ts DESC LIMIT 1""",
                tenant, collector_id,
            )
    return {"collector": dict(row), "last_heartbeat": dict(hb) if hb else None}


@router.get("/entities/{entity}/metrics")
async def entity_metrics(entity: str, request: Request,
                         since: datetime | None = None, limit: int = Query(200, ge=1, le=2000)):
    tenant = tenant_from_request(request)
    since = since or datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT entity,metric,event_ts,source_tz,avg,min,max,p95,count
                   FROM metric_points WHERE tenant_id=$1 AND entity=$2 AND event_ts >= $3
                   ORDER BY event_ts DESC LIMIT $4""",
                tenant, entity, since, limit,
            )
    return {"entity": entity, "metrics": [dict(r) for r in rows]}


@router.get("/entities/{entity}/health-history")
async def health_history(entity: str, request: Request, limit: int = Query(100, ge=1, le=1000)):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT from_state,to_state,reasons,at_utc FROM health_transitions
                   WHERE tenant_id=$1 AND entity=$2 ORDER BY at_utc DESC LIMIT $3""",
                tenant, entity, limit,
            )
    return {"entity": entity, "transitions": [dict(r) for r in rows]}


@router.get("/alerts")
async def alerts(request: Request, status: str | None = None, severity: str | None = None,
                 since: datetime | None = None, limit: int = Query(100, ge=1, le=1000)):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT alert_id,entity,rule,severity,status,first_ts,last_ts,
                          occurrences,context FROM alerts
                   WHERE tenant_id=$1
                     AND ($2::text IS NULL OR status=$2)
                     AND ($3::text IS NULL OR severity=$3)
                     AND ($4::timestamptz IS NULL OR last_ts >= $4)
                   ORDER BY last_ts DESC LIMIT $5""",
                tenant, status, severity, since, limit,
            )
    return {"alerts": [dict(r) for r in rows]}


@router.get("/slo")
async def slo(request: Request, limit: int = Query(1000, ge=1, le=10000)):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT kind,sample_key,event_ts,observed_ts,delay_ms
                   FROM slo_samples WHERE tenant_id=$1 ORDER BY event_ts DESC LIMIT $2""",
                tenant, limit,
            )
    return {"samples": [dict(r) for r in rows]}


class RenderAck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sample_key: str = Field(min_length=1, max_length=128)
    rendered_at: datetime
    source_event_ts: datetime


@router.post("/slo/render-ack", status_code=202)
async def render_ack(payload: RenderAck, request: Request):
    tenant = tenant_from_request(request)
    rendered = payload.rendered_at
    source_event = payload.source_event_ts
    if rendered.tzinfo is None or source_event.tzinfo is None:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"})
    rendered = rendered.astimezone(timezone.utc)
    source_event = source_event.astimezone(timezone.utc)
    observed = datetime.now(timezone.utc)
    if rendered > observed or source_event > rendered:
        raise HTTPException(422, detail={"code": "INVALID_RENDER_TIMESTAMPS"})
    # Architecture §22 defines delay as browser rendered_at minus source event_ts.
    delay_ms = int((rendered - source_event).total_seconds() * 1000)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            await conn.execute(
                """INSERT INTO slo_samples
                   (tenant_id,kind,sample_key,event_ts,observed_ts,delay_ms)
                   VALUES($1,'collection_to_dashboard', $2, $3, $4, $5)
                   ON CONFLICT(tenant_id,kind,sample_key,event_ts) DO NOTHING""",
                tenant, payload.sample_key, source_event, observed, delay_ms,
            )
            await conn.execute(
                """INSERT INTO audit_events
                   (tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'slo.render_ack','slo_sample',$3,$4::jsonb)""",
                tenant, request.state.user_id, payload.sample_key,
                json.dumps({"delay_ms": delay_ms, "rendered_at": rendered.isoformat(), "source_event_ts": source_event.isoformat(), "ack_received_at": observed.isoformat()}),
            )
    return {"accepted": True, "delay_ms": delay_ms}


@router.get("/payloads/{payload_id}")
async def payload_receipt(payload_id: UUID, request: Request):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            row = await conn.fetchrow(
                """SELECT payload_id,collector_id,seq,payload_hash,sent_at,received_at
                   FROM ingest_receipts WHERE tenant_id=$1 AND payload_id=$2""",
                tenant, payload_id,
            )
    if not row:
        raise HTTPException(404, detail={"code": "PAYLOAD_NOT_FOUND"})
    return {"receipt": dict(row)}


@router.get("/audit")
async def audit_events(request: Request, limit: int = Query(100, ge=1, le=1000)):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT actor_id,action,resource_type,resource_id,details,at_utc
                   FROM audit_events WHERE tenant_id=$1 ORDER BY at_utc DESC LIMIT $2""",
                tenant, limit,
            )
    return {"events": [dict(r) for r in rows]}


@router.get("/slo/judge-mode")
async def judge_mode_slo(request: Request):
    """Return rolling five-minute and since-start SLO measurements."""
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT kind,
                          count(*) FILTER (WHERE event_ts >= now() - INTERVAL '5 minutes') AS recent_count,
                          percentile_cont(0.50) WITHIN GROUP (ORDER BY delay_ms)
                            FILTER (WHERE event_ts >= now() - INTERVAL '5 minutes') AS recent_p50_ms,
                          percentile_cont(0.95) WITHIN GROUP (ORDER BY delay_ms)
                            FILTER (WHERE event_ts >= now() - INTERVAL '5 minutes') AS recent_p95_ms,
                          max(delay_ms) FILTER (WHERE event_ts >= now() - INTERVAL '5 minutes') AS recent_max_ms,
                          count(*) AS total_count,
                          percentile_cont(0.95) WITHIN GROUP (ORDER BY delay_ms) AS lifetime_p95_ms,
                          max(observed_ts) AS latest_sample
                   FROM slo_samples WHERE tenant_id=$1 GROUP BY kind ORDER BY kind""",
                tenant,
            )
    measured = {}
    for row in rows:
        measured[row["kind"]] = {
            "recent_5m": {
                "sample_count": row["recent_count"],
                "p50_ms": float(row["recent_p50_ms"]) if row["recent_p50_ms"] is not None else None,
                "p95_ms": float(row["recent_p95_ms"]) if row["recent_p95_ms"] is not None else None,
                "max_ms": row["recent_max_ms"],
            },
            "since_start": {
                "sample_count": row["total_count"],
                "p95_ms": float(row["lifetime_p95_ms"]) if row["lifetime_p95_ms"] is not None else None,
            },
            "latest_sample": row["latest_sample"],
        }
    def p95(kind):
        item = measured.get(kind, {}).get("recent_5m", {}).get("p95_ms")
        return item
    def evaluate(kind, target):
        value = p95(kind)
        return "insufficient_data" if value is None else ("pass" if value <= target else "fail")
    rec = measured.get("reconciliation_missing_sequences", {}).get("recent_5m", {})
    rec_count = rec.get("sample_count", 0)
    rec_max = rec.get("max_ms")
    return {
        "window": "rolling_5m_and_since_start",
        "targets": {
            "collection_to_dashboard_p95_ms": 10000,
            "threshold_to_alert_p95_ms": 15000,
            "collector_offline_detection_ms": 60000,
            "reconciliation_missing_sequences": 0,
            "reconciliation_duplicates": 0,
        },
        "measured": measured,
        "evaluation": {
            "collection_to_dashboard": evaluate("collection_to_dashboard", 10000),
            "threshold_to_alert": evaluate("threshold_to_alert", 15000),
            "collector_offline_detection": evaluate("collector_offline_detection", 60000),
            "reconciliation_missing_sequences": (
                "insufficient_data" if not rec_count else ("pass" if rec_max == 0 else "fail")
            ),
            "reconciliation_duplicate_protection": "database_unique_constraint_enforced; duplicate_attempt_count_not_yet_measured",
        },
        "notes": [
            "Latency is rendered_at minus source_event_ts; the acknowledgement receipt timestamp is retained separately.",
            "Offline delay is watchdog detection time minus the last heartbeat timestamp.",
            "Reconciliation sample values are missing-sequence counts, not milliseconds.",
            "Duplicate attempts are rejected by the unique collector sequence constraint; an operational counter is not yet instrumented.",
        ],
    }


class ThresholdUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    good: float = Field(ge=0)
    fair: float = Field(ge=0)
    poor: float = Field(ge=0)
    hysteresis: float = Field(default=0.10, ge=0, le=0.5)


@router.put("/thresholds/{metric}")
async def update_thresholds(metric: str, payload: ThresholdUpdate, request: Request):
    tenant = await require_role(request, {"tenant_admin"})
    if not (payload.good < payload.fair < payload.poor):
        raise HTTPException(422, detail={"code": "THRESHOLDS_MUST_BE_STRICTLY_INCREASING"})
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            await conn.execute(
                """INSERT INTO thresholds(tenant_id,metric,good,fair,poor,hysteresis,updated_at)
                   VALUES($1,$2,$3,$4,$5,$6,now())
                   ON CONFLICT(tenant_id,metric) DO UPDATE
                   SET good=EXCLUDED.good,fair=EXCLUDED.fair,poor=EXCLUDED.poor,
                       hysteresis=EXCLUDED.hysteresis,updated_at=now()""",
                tenant, metric, payload.good, payload.fair, payload.poor, payload.hysteresis,
            )
            await conn.execute(
                """INSERT INTO audit_events
                   (tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'threshold.updated','threshold',$3,$4::jsonb)""",
                tenant, str(request.state.user_id), metric,
                json.dumps(payload.model_dump()),
            )
    return {"metric": metric, **payload.model_dump(), "updated": True}


@router.get("/incidents")
async def incidents(request: Request, status: str | None = None,
                    limit: int = Query(100, ge=1, le=1000)):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT incident_id,title,severity,status,summary,opened_at,updated_at,closed_at
                   FROM incidents WHERE tenant_id=$1 AND ($2::text IS NULL OR status=$2)
                   ORDER BY updated_at DESC LIMIT $3""",
                tenant, status, limit,
            )
    return {"incidents": [dict(row) for row in rows]}


@router.get("/incidents/{incident_id}")
async def incident_detail(incident_id: UUID, request: Request):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            row = await conn.fetchrow(
                """SELECT incident_id,title,severity,status,summary,opened_at,updated_at,closed_at
                   FROM incidents WHERE tenant_id=$1 AND incident_id=$2""",
                tenant, incident_id,
            )
            if not row:
                raise HTTPException(404, detail={"code": "INCIDENT_NOT_FOUND"})
            links = await conn.fetch(
                """SELECT recommendation_id,payload_id,evidence_type,reference
                   FROM evidence_links WHERE tenant_id=$1 AND incident_id=$2
                   ORDER BY created_at""",
                tenant, incident_id,
            )
    return {"incident": dict(row), "evidence_links": [dict(item) for item in links]}


@router.get("/recommendations/{recommendation_id}")
async def recommendation_detail(recommendation_id: UUID, request: Request):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            row = await conn.fetchrow(
                """SELECT recommendation_id,incident_id,title,rationale,confidence,status,evidence,created_at
                   FROM recommendations WHERE tenant_id=$1 AND recommendation_id=$2""",
                tenant, recommendation_id,
            )
            if not row:
                raise HTTPException(404, detail={"code": "RECOMMENDATION_NOT_FOUND"})
            links = await conn.fetch(
                """SELECT payload_id,evidence_type,reference
                   FROM evidence_links WHERE tenant_id=$1 AND recommendation_id=$2
                   ORDER BY created_at""",
                tenant, recommendation_id,
            )
    return {"recommendation": dict(row), "evidence_links": [dict(item) for item in links]}
