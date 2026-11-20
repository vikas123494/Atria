"""Pull-based, signed action delivery and audited two-person approval."""
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from cloud.app.api import require_role, tenant_from_request
from cloud.app.security import authenticate_collector

router = APIRouter(tags=["actions"])


class ActionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collector_id: str = Field(min_length=1, max_length=128)
    action_type: str = Field(min_length=1, max_length=64)
    params: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    policy_ref: str = Field(min_length=1, max_length=128)
    expires_in_seconds: int = Field(default=900, ge=60, le=3600)


class ActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    local_policy_decision: str
    health_before: str | None = None
    health_after: str | None = None
    ts: datetime


@router.post("/api/v1/actions", status_code=201)
async def create_action(payload: ActionCreate, request: Request):
    tenant = await require_role(request, {"operator", "tenant_admin"})
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
                   (action_id,tenant_id,collector_id,action_type,params,policy_ref,status,
                    requested_by,created_at,expires_at)
                   VALUES($1,$2,$3,$4,$5::jsonb,$6,'pending',$7,$8,$9)""",
                action_id, tenant, payload.collector_id, payload.action_type,
                json.dumps(payload.params), payload.policy_ref, str(request.state.user_id),
                now, now + timedelta(seconds=payload.expires_in_seconds),
            )
            await conn.execute(
                """INSERT INTO audit_events
                   (tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'action.requested','action',$3,$4::jsonb)""",
                tenant, str(request.state.user_id), str(action_id),
                json.dumps({"action_type": payload.action_type, "policy_ref": payload.policy_ref}),
            )
    return {"action_id": str(action_id), "status": "pending",
            "expires_at": now + timedelta(seconds=payload.expires_in_seconds)}


async def _decide_action(action_id: UUID, request: Request, decision: str):
    tenant = await require_role(request, {"approver", "tenant_admin"})
    now = datetime.now(timezone.utc)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            action = await conn.fetchrow(
                "SELECT requested_by FROM actions WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
                tenant, action_id,
            )
            if not action:
                raise HTTPException(404, detail={"code": "ACTION_NOT_FOUND"})
            if str(action["requested_by"]) == str(request.state.user_id):
                raise HTTPException(403, detail={"code": "TWO_PERSON_APPROVAL_REQUIRED"})
            if decision == "approve":
                row = await conn.fetchrow(
                    """UPDATE actions SET status='approved',approved_by=$3,approved_at=$4
                       WHERE tenant_id=$1 AND action_id=$2 AND status='pending'
                         AND expires_at>$4 RETURNING action_id""",
                    tenant, action_id, str(request.state.user_id), now,
                )
            else:
                row = await conn.fetchrow(
                    """UPDATE actions SET status='rejected',approved_by=$3,rejected_at=$4
                       WHERE tenant_id=$1 AND action_id=$2 AND status='pending'
                         AND expires_at>$4 RETURNING action_id""",
                    tenant, action_id, str(request.state.user_id), now,
                )
            if not row:
                raise HTTPException(409, detail={"code": "ACTION_NOT_DECIDABLE"})
            await conn.execute(
                """INSERT INTO audit_events
                   (tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,$3,'action',$4,$5::jsonb)""",
                tenant, str(request.state.user_id), f"action.{decision}", str(action_id),
                json.dumps({"requested_by": str(action["requested_by"])}),
            )
    return {"action_id": str(action_id), "status": "approved" if decision == "approve" else "rejected"}


@router.post("/api/v1/actions/{action_id}/approve")
async def approve_action(action_id: UUID, request: Request):
    return await _decide_action(action_id, request, "approve")


@router.post("/api/v1/actions/{action_id}/reject")
async def reject_action(action_id: UUID, request: Request):
    return await _decide_action(action_id, request, "reject")


@router.get("/v1/actions")
async def pull_actions(request: Request, after: UUID | None = None):
    body = await request.body()
    auth, collector = await authenticate_collector(request, body)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", collector["tenant_id"])
            rows = await conn.fetch(
                """UPDATE actions SET status='delivered',delivered_at=now()
                   WHERE tenant_id=$1 AND collector_id=$2 AND status='approved'
                     AND expires_at>now() AND ($3::uuid IS NULL OR action_id>$3)
                   RETURNING action_id,action_type,params,policy_ref,approved_by,expires_at""",
                collector["tenant_id"], auth.collector_id, after,
            )
    result = {
        "collector_id": auth.collector_id,
        "actions": [
            {"action_id": str(r["action_id"]), "type": r["action_type"],
             "target": auth.collector_id, "params": r["params"],
             "policy_ref": r["policy_ref"], "approved_by": r["approved_by"],
             "expires_at": r["expires_at"].isoformat()}
            for r in rows
        ],
    }
    result["sig"] = request.app.state.receipt_signer.sign(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    )
    return result


@router.post("/v1/actions/{action_id}/result", status_code=204)
async def action_result(action_id: UUID, payload: ActionResult, request: Request):
    body = await request.body()
    auth, collector = await authenticate_collector(request, body)
    allowed = {"dry_run_ok", "executed", "rolled_back", "vetoed"}
    if payload.status not in allowed or payload.local_policy_decision not in {"allow", "deny"}:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"})
    if payload.ts.tzinfo is None:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"})
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", collector["tenant_id"])
            row = await conn.fetchrow(
                """UPDATE actions SET status=$4,result=$5::jsonb,
                       executed_at=CASE WHEN $4 IN ('executed','rolled_back') THEN now() ELSE executed_at END
                   WHERE tenant_id=$1 AND collector_id=$2 AND action_id=$3
                     AND status='delivered' AND expires_at>now()
                   RETURNING action_id""",
                collector["tenant_id"], auth.collector_id, action_id, payload.status,
                json.dumps(payload.model_dump(mode="json")),
            )
            if not row:
                raise HTTPException(409, detail={"code": "ACTION_RESULT_NOT_ACCEPTED"})
            await conn.execute(
                """INSERT INTO audit_events
                   (tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'action.result','action',$3,$4::jsonb)""",
                collector["tenant_id"], auth.collector_id, str(action_id),
                json.dumps(payload.model_dump(mode="json")),
            )
    return None
