"""Pull-only safe remediation action APIs."""
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from cloud.app.api import tenant_from_request
from cloud.app.security import authenticate_collector

router = APIRouter(tags=["actions"])


class ActionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collector_id: str = Field(min_length=1, max_length=128)
    action_type: str = Field(min_length=1, max_length=64)
    params: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    expires_in_seconds: int = Field(default=900, ge=60, le=3600)


@router.post("/api/v1/actions", status_code=201)
async def create_action(payload: ActionCreate, request: Request):
    tenant = tenant_from_request(request)
    action_id = uuid4()
    now = datetime.now(timezone.utc)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            collector = await conn.fetchrow(
                "SELECT collector_id FROM collectors WHERE tenant_id=$1 AND collector_id=$2 AND revoked_at IS NULL",
                tenant, payload.collector_id,
            )
            if not collector:
                raise HTTPException(404, detail={"code": "COLLECTOR_NOT_FOUND"})
            await conn.execute(
                """INSERT INTO actions
                   (action_id,tenant_id,collector_id,action_type,params,status,
                    requested_by,created_at,expires_at)
                   VALUES($1,$2,$3,$4,$5::jsonb,'pending',$6,$7,$8)""",
                action_id, tenant, payload.collector_id, payload.action_type,
                json.dumps(payload.params), request.state.user_id, now,
                now + timedelta(seconds=payload.expires_in_seconds),
            )
            await conn.execute(
                """INSERT INTO audit_events
                   (tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'action.requested','action',$3,$4::jsonb)""",
                tenant, request.state.user_id, str(action_id),
                json.dumps({"action_type": payload.action_type}),
            )
    return {"action_id": str(action_id), "status": "pending", "expires_at": now + timedelta(seconds=payload.expires_in_seconds)}


@router.post("/api/v1/actions/{action_id}/approve")
async def approve_action(action_id: UUID, request: Request):
    tenant = tenant_from_request(request)
    now = datetime.now(timezone.utc)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            row = await conn.fetchrow(
                """UPDATE actions SET status='approved',approved_by=$3,approved_at=$4
                   WHERE tenant_id=$1 AND action_id=$2 AND status='pending'
                     AND expires_at>$4 RETURNING action_id""",
                tenant, action_id, request.state.user_id, now,
            )
            if not row:
                raise HTTPException(409, detail={"code": "ACTION_NOT_APPROVABLE"})
            await conn.execute(
                """INSERT INTO audit_events
                   (tenant_id,actor_id,action,resource_type,resource_id)
                   VALUES($1,$2,'action.approved','action',$3)""",
                tenant, request.state.user_id, str(action_id),
            )
    return {"action_id": str(action_id), "status": "approved"}


@router.get("/v1/actions")
async def pull_actions(request: Request, after: str = "1970-01-01T00:00:00+00:00"):
    body = await request.body()
    auth, collector = await authenticate_collector(request, body)
    try:
        cursor = datetime.fromisoformat(after.replace("Z", "+00:00"))
        if cursor.tzinfo is None:
            raise ValueError
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"}) from exc
    async with request.app.state.db_pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.tenant_id',$1,true)", collector["tenant_id"])
        rows = await conn.fetch(
            """UPDATE actions SET status='delivered',delivered_at=now()
               WHERE tenant_id=$1 AND collector_id=$2 AND status='approved'
                 AND expires_at>now() AND created_at>$3
               RETURNING action_id,action_type,params,expires_at,approved_at""",
            collector["tenant_id"], auth.collector_id, cursor,
        )
    result = {
        "collector_id": auth.collector_id,
        "actions": [
            {"action_id": str(r["action_id"]), "action_type": r["action_type"],
             "params": r["params"], "expires_at": r["expires_at"].isoformat(),
             "approved_at": r["approved_at"].isoformat()}
            for r in rows
        ],
    }
    import hashlib
    import json as _json
    result["sig"] = request.app.state.receipt_signer.sign(
        _json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    )
    return result
