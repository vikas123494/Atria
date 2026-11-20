"""Tenant-scoped Server-Sent Events for dashboard updates."""
import asyncio
import json
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from cloud.app.api import tenant_from_request

router = APIRouter(prefix="/api/v1", tags=["dashboard-events"])


@router.get("/events")
async def events(request: Request):
    tenant = tenant_from_request(request)
    channel = f"veilops:tenant:{tenant}:events"

    async def stream():
        pubsub = request.app.state.redis.pubsub()
        await pubsub.subscribe(channel)
        try:
            yield "event: connected\ndata: {\"status\":\"connected\"}\n\n"
            while not await request.is_disconnected():
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=15.0
                )
                if message and message.get("type") == "message":
                    try:
                        payload = json.loads(message["data"])
                    except (TypeError, ValueError):
                        continue
                    yield f"event: {payload.get('event','update')}\ndata: {json.dumps(payload, separators=(',',':'))}\n\n"
                else:
                    yield ": keepalive\n\n"
                await asyncio.sleep(0)
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()

    return StreamingResponse(
        stream(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
