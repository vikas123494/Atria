"""Regional collector ingest endpoints (Architecture §§12–13)."""
import hashlib
import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from cloud.app.contracts import Envelope
from cloud.app.security import authenticate_collector

router = APIRouter(prefix="/v1", tags=["collector-ingest"])
MAX_BODY_BYTES = 1_048_576


@router.post("/ingest")
async def ingest(request: Request):
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, detail={"code": "PAYLOAD_TOO_LARGE"})
    auth, collector = await authenticate_collector(request, body)
    try:
        envelope = Envelope.model_validate_json(body)
    except ValidationError as exc:
        message = str(exc)
        code = "UNKNOWN_RECORD_TYPE" if "UNKNOWN_RECORD_TYPE" in message else "SCHEMA_VIOLATION"
        raise HTTPException(422, detail={"code": code, "errors": exc.errors(include_input=False)}) from exc

    if envelope.collector_id != auth.collector_id:
        raise HTTPException(403, detail={"code": "TENANT_MISMATCH"})
    if envelope.tenant_id != collector["tenant_id"]:
        raise HTTPException(403, detail={"code": "TENANT_MISMATCH"})
    if envelope.region != collector["region"] or envelope.region != request.app.state.settings.region:
        raise HTTPException(403, detail={"code": "WRONG_REGION", "correct_region": collector["region"]})

    idem = request.headers.get("idempotency-key")
    if idem != str(envelope.payload_id):
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION", "field": "Idempotency-Key"})

    payload_hash = "sha256:" + hashlib.sha256(body).hexdigest()
    sent_at = envelope.sent_at.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    if abs((now - sent_at).total_seconds()) > 86400:
        # Sent-at is a clock-skew signal, not the replay defense; the signed
        # request timestamp has the strict ±300 second window.
        pass

    redis = request.app.state.redis
    try:
        await redis.ping()
    except Exception as exc:
        raise HTTPException(503, detail={"code": "STREAM_UNAVAILABLE"}) from exc
    rate_key = f"rate:{auth.collector_id}:{int(now.timestamp()) // 60}"
    count = await redis.incr(rate_key)
    if count == 1:
        await redis.expire(rate_key, 60)
    if count > request.app.state.settings.ingest_rate_per_minute:
        raise HTTPException(429, detail={"code": "RATE_LIMITED"}, headers={"Retry-After": "60"})

    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", envelope.tenant_id)
            existing = await conn.fetchrow(
                "SELECT payload_hash, received_at FROM ingest_receipts WHERE tenant_id=$1 AND payload_id=$2",
                envelope.tenant_id, envelope.payload_id,
            )
            if existing:
                if existing["payload_hash"] != payload_hash:
                    raise HTTPException(409, detail={"code": "IDEMPOTENCY_CONFLICT"})
                receipt = {
                    "payload_id": str(envelope.payload_id), "payload_hash": payload_hash,
                    "status": "duplicate", "received_at": existing["received_at"].isoformat(),
                    "highest_contiguous_seq": await _highest_contiguous(conn, envelope.tenant_id, auth.collector_id),
                }
                receipt["sig"] = request.app.state.receipt_signer.sign(
                    json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
                )
                return JSONResponse(status_code=200, content=receipt)

            try:
                await conn.execute(
                    """INSERT INTO ingest_receipts
                       (tenant_id,payload_id,collector_id,seq,payload_hash,sent_at,received_at)
                       VALUES($1,$2,$3,$4,$5,$6,$7)""",
                    envelope.tenant_id, envelope.payload_id, auth.collector_id,
                    envelope.seq, payload_hash, sent_at, now,
                )
            except Exception as exc:
                # A collector sequence collision is a protocol conflict, not a retryable success.
                if "uq_ingest_collector_seq" in str(exc):
                    raise HTTPException(409, detail={"code": "SEQUENCE_CONFLICT"}) from exc
                raise

            event_times = [
                datetime.fromisoformat(record["event_ts"].replace("Z", "+00:00"))
                for record in envelope.records if record.get("event_ts")
            ]
            if event_times:
                oldest_event = min(event_times)
                ingest_delay_ms = max(0, int((now - oldest_event).total_seconds() * 1000))
                await conn.execute(
                    """INSERT INTO slo_samples
                       (tenant_id,kind,sample_key,event_ts,observed_ts,delay_ms)
                       VALUES($1,'collection_to_ingest',$2,$3,$4,$5)
                       ON CONFLICT DO NOTHING""",
                    envelope.tenant_id, str(envelope.payload_id), oldest_event, now, ingest_delay_ms,
                )

            # Receipt and dispatch intent commit atomically in PostgreSQL.
            # A background publisher retries Redis delivery after transient failures.
            await conn.execute(
                """INSERT INTO ingest_stream_outbox
                   (tenant_id,collector_id,payload_id,seq,payload_hash,sent_at,received_at,body)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
                   ON CONFLICT(tenant_id,payload_id) DO NOTHING""",
                envelope.tenant_id, auth.collector_id, envelope.payload_id,
                envelope.seq, payload_hash, sent_at, now, body.decode("utf-8"),
            )

    receipt = {
        "payload_id": str(envelope.payload_id), "payload_hash": payload_hash,
        "status": "stored", "received_at": now.isoformat(),
        "highest_contiguous_seq": envelope.seq,
    }
    receipt["sig"] = request.app.state.receipt_signer.sign(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    )
    return JSONResponse(status_code=202, content=receipt)


async def _highest_contiguous(conn, tenant_id: str, collector_id: str) -> int:
    # Sequence values are monotonic per collector; calculate the contiguous prefix.
    rows = await conn.fetch(
        """SELECT seq FROM ingest_receipts
           WHERE tenant_id=$1 AND collector_id=$2 ORDER BY seq""",
        tenant_id, collector_id,
    )
    expected = 1
    for row in rows:
        if row["seq"] != expected:
            break
        expected += 1
    return expected - 1


@router.post("/heartbeat", status_code=204)
async def heartbeat(request: Request):
    body = await request.body()
    auth, collector = await authenticate_collector(request, body)
    try:
        data = json.loads(body)
        required = {"collector_id", "tenant_id", "ts", "version", "uptime_s",
                    "cpu_pct", "mem_mb", "outbox_depth", "oldest_unsent_s",
                    "last_acked_seq", "policy_version", "config_hash", "sources_ok"}
        if not required.issubset(data):
            raise ValueError("missing heartbeat fields")
        if data["collector_id"] != auth.collector_id or data["tenant_id"] != collector["tenant_id"]:
            raise HTTPException(403, detail={"code": "TENANT_MISMATCH"})
        if collector["region"] != request.app.state.settings.region:
            raise HTTPException(403, detail={"code": "WRONG_REGION", "correct_region": collector["region"]})
        ts = datetime.fromisoformat(data["ts"].replace("Z", "+00:00"))
        if ts.tzinfo is None:
            raise ValueError("ts must be timezone-aware")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"}) from exc

    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", collector["tenant_id"])
            await conn.execute(
                """INSERT INTO collector_heartbeats(tenant_id,collector_id,ts,body)
                   VALUES($1,$2,$3,$4::jsonb)
                   ON CONFLICT(tenant_id,collector_id,ts) DO NOTHING""",
                collector["tenant_id"], auth.collector_id, ts, json.dumps(data),
            )
    return Response(status_code=204)
