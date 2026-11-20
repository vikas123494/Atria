"""Collector/cloud sequence reconciliation API (Architecture §§13, 17)."""
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from cloud.app.security import authenticate_collector

router = APIRouter(prefix="/v1", tags=["reconciliation"])


@router.get("/reconcile")
async def reconcile(request: Request, collector_id: str,
                    from_seq: int = Query(ge=1), to_seq: int = Query(ge=1)):
    if to_seq < from_seq or to_seq - from_seq > 10000:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"})
    # The request signature covers the exact query string so the requested
    # reconciliation range cannot be changed independently of its HMAC.
    body = await request.body()
    auth, collector = await authenticate_collector(request, body)
    if collector_id != auth.collector_id:
        raise HTTPException(403, detail={"code": "TENANT_MISMATCH"})

    observed = datetime.now(timezone.utc)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.tenant_id',$1,true)", collector["tenant_id"]
            )
            rows = await conn.fetch(
                """SELECT seq FROM ingest_receipts
                   WHERE tenant_id=$1 AND collector_id=$2 AND seq BETWEEN $3 AND $4
                   ORDER BY seq""",
                collector["tenant_id"], collector_id, from_seq, to_seq,
            )
            received = {row["seq"] for row in rows}
            missing = [seq for seq in range(from_seq, to_seq + 1) if seq not in received]
            await conn.execute(
                """INSERT INTO slo_samples
                   (tenant_id,kind,sample_key,event_ts,observed_ts,delay_ms)
                   VALUES($1,'reconciliation_missing_sequences',$2,$3,$3,$4)
                   ON CONFLICT DO NOTHING""",
                collector["tenant_id"], f"{collector_id}:{from_seq}:{to_seq}",
                observed, len(missing),
            )
    return {
        "collector_id": collector_id, "tenant_id": collector["tenant_id"],
        "from_seq": from_seq, "to_seq": to_seq,
        "received_count": len(received), "missing_sequences": missing,
        "reconciled": not missing,
    }
