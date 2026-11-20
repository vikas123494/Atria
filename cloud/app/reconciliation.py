"""Collector/cloud sequence reconciliation API (Architecture §13, §17)."""
from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/v1", tags=["reconciliation"])


@router.get("/reconcile")
async def reconcile(request: Request, collector_id: str,
                    from_seq: int = Query(ge=1), to_seq: int = Query(ge=1)):
    if to_seq < from_seq or to_seq - from_seq > 10000:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"})
    async with request.app.state.db_pool.acquire() as conn:
        collector = await conn.fetchrow(
            "SELECT tenant_id,region FROM collectors WHERE collector_id=$1 AND revoked_at IS NULL",
            collector_id,
        )
        if not collector:
            raise HTTPException(404, detail={"code": "COLLECTOR_NOT_FOUND"})
        await conn.execute("SELECT set_config('app.tenant_id',$1,true)", collector["tenant_id"])
        rows = await conn.fetch(
            """SELECT seq FROM ingest_receipts
               WHERE tenant_id=$1 AND collector_id=$2 AND seq BETWEEN $3 AND $4
               ORDER BY seq""",
            collector["tenant_id"], collector_id, from_seq, to_seq,
        )
    received = {row["seq"] for row in rows}
    missing = [seq for seq in range(from_seq, to_seq + 1) if seq not in received]
    return {
        "collector_id": collector_id, "tenant_id": collector["tenant_id"],
        "from_seq": from_seq, "to_seq": to_seq,
        "received_count": len(received), "missing_sequences": missing,
        "reconciled": not missing,
    }
