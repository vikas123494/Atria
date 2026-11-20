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
