"""Tenant-scoped dashboard and operational APIs (Person C backend scope)."""
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/api/v1", tags=["dashboard-api"])


def tenant_from_request(request: Request) -> str:
    # Authentication middleware must populate this from a verified JWT claim.
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(401, detail={"code": "UNAUTHENTICATED"})
    return tenant_id


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
    return {"tenant_id": tenant, "collectors": [dict(r) for r in rows]}


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
async def alerts(request: Request, limit: int = Query(100, ge=1, le=1000)):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT alert_id,entity,rule,severity,status,first_ts,last_ts,
                          occurrences,context FROM alerts
                   WHERE tenant_id=$1 ORDER BY last_ts DESC LIMIT $2""",
                tenant, limit,
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


from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict, Field


class RenderAck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sample_key: str = Field(min_length=1, max_length=128)
    rendered_at: datetime


@router.post("/slo/render-ack", status_code=202)
async def render_ack(payload: RenderAck, request: Request):
    tenant = tenant_from_request(request)
    rendered = payload.rendered_at
    if rendered.tzinfo is None:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"})
    rendered = rendered.astimezone(timezone.utc)
    observed = datetime.now(timezone.utc)
    delay_ms = max(0, int((observed - rendered).total_seconds() * 1000))
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            await conn.execute(
                """INSERT INTO slo_samples
                   (tenant_id,kind,sample_key,event_ts,observed_ts,delay_ms)
                   VALUES($1,'dashboard_render', $2, $3, $4, $5)
                   ON CONFLICT(tenant_id,kind,sample_key,event_ts) DO NOTHING""",
                tenant, payload.sample_key, rendered, observed, delay_ms,
            )
            await conn.execute(
                """INSERT INTO audit_events
                   (tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'slo.render_ack','slo_sample',$3,$4::jsonb)""",
                tenant, request.state.user_id, payload.sample_key,
                __import__("json").dumps({"delay_ms": delay_ms}),
            )
    return {"accepted": True, "delay_ms": delay_ms}


from uuid import UUID


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
    """Return measured SLOs and explicitly identify metrics not yet instrumented."""
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await conn.fetch(
                """SELECT kind, count(*) AS sample_count,
                          percentile_cont(0.95) WITHIN GROUP (ORDER BY delay_ms) AS p95_ms,
                          max(observed_ts) AS latest_sample
                   FROM slo_samples
                   WHERE tenant_id=$1 AND event_ts >= now() - INTERVAL '24 hours'
                   GROUP BY kind ORDER BY kind""",
                tenant,
            )
    measured = {row["kind"]: {
        "sample_count": row["sample_count"],
        "p95_ms": float(row["p95_ms"]) if row["p95_ms"] is not None else None,
        "latest_sample": row["latest_sample"],
    } for row in rows}

    alert = measured.get("threshold_to_alert")
    alert_p95 = alert["p95_ms"] if alert else None
    return {
        "window": "24h",
        "targets": {
            "collection_to_dashboard_p95_ms": 10000,
            "threshold_to_alert_p95_ms": 15000,
            "collector_offline_detection_ms": 60000,
            "reconciliation_loss": 0,
            "reconciliation_duplicates": 0,
        },
        "measured": measured,
        "evaluation": {
            "threshold_to_alert": (
                "insufficient_data" if alert_p95 is None
                else "pass" if alert_p95 <= 15000 else "fail"
            ),
            "collection_to_dashboard": "not_instrumented_end_to_end",
            "collector_offline_detection": "not_instrumented_as_slo_sample",
            "reconciliation": "not_instrumented_as_slo_sample",
        },
        "notes": [
            "p95 is calculated from observed samples in the last 24 hours.",
            "dashboard_render samples measure render-ack receipt delay, not collection-to-dashboard end-to-end latency.",
            "A missing measurement is reported as not instrumented, never as a passing SLO.",
        ],
    }
