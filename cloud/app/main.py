"""VeilOps regional Cloud Core API."""
import asyncio
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI, HTTPException, Request
from redis.asyncio import Redis

from cloud.app.actions import router as actions_router
from cloud.app.api import router as dashboard_router
from cloud.app.auth import TenantJWTMiddleware
from cloud.app.control import router as control_router
from cloud.app.crypto import ReceiptSigner, SecretBox
from cloud.app.events import router as events_router
from cloud.app.health import late_metric_recompute_loop, watchdog_loop
from cloud.app.ingest import router as ingest_router
from cloud.app.processor import StreamProcessor, stream_outbox_publisher
from cloud.app.reconciliation import router as reconciliation_router
from cloud.app.settings import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    app.state.settings = settings
    app.state.secret_box = SecretBox.from_environment()
    app.state.receipt_signer = ReceiptSigner.from_environment()
    app.state.db_pool = await asyncpg.create_pool(
        settings.database_url, min_size=1,
        max_size=settings.database_pool_max, command_timeout=5,
    )
    app.state.redis = Redis.from_url(
        settings.redis_url, encoding="utf-8", decode_responses=True,
        socket_connect_timeout=2, socket_timeout=2,
    )
    app.state.processor_stop = asyncio.Event()
    app.state.watchdog_stop = asyncio.Event()
    app.state.recompute_stop = asyncio.Event()
    app.state.publisher_stop = asyncio.Event()
    processor = StreamProcessor(app.state.redis, app.state.db_pool, settings.ingest_stream)
    app.state.processor_task = asyncio.create_task(
        processor.run(app.state.processor_stop), name="veilops-stream-writer"
    )
    app.state.publisher_task = asyncio.create_task(
        stream_outbox_publisher(app.state.redis, app.state.db_pool, settings.ingest_stream,
                                stop_event=app.state.publisher_stop),
        name="veilops-ingest-outbox-publisher",
    )
    app.state.watchdog_task = asyncio.create_task(
        watchdog_loop(app.state.db_pool, stop_event=app.state.watchdog_stop),
        name="veilops-health-watchdog",
    )
    app.state.recompute_task = asyncio.create_task(
        late_metric_recompute_loop(app.state.db_pool, stop_event=app.state.recompute_stop),
        name="veilops-late-metric-recompute",
    )
    try:
        yield
    finally:
        app.state.processor_stop.set()
        app.state.watchdog_stop.set()
        app.state.recompute_stop.set()
        app.state.publisher_stop.set()
        app.state.processor_task.cancel()
        app.state.watchdog_task.cancel()
        app.state.recompute_task.cancel()
        app.state.publisher_task.cancel()
        for task in (app.state.processor_task, app.state.watchdog_task, app.state.recompute_task, app.state.publisher_task):
            try:
                await task
            except asyncio.CancelledError:
                pass
        await app.state.redis.aclose()
        await app.state.db_pool.close()


app = FastAPI(
    title="VeilOps Cloud Core", version="0.3.0",
    description="Metadata-only, multi-tenant regional cloud services.",
    lifespan=lifespan,
)
app.include_router(ingest_router)
app.include_router(control_router)
app.include_router(reconciliation_router)
app.include_router(dashboard_router)
app.include_router(events_router)
app.include_router(actions_router)
app.add_middleware(TenantJWTMiddleware)


@app.get("/health/live", tags=["health"])
async def liveness():
    return {"status": "alive"}


@app.get("/health/ready", tags=["health"])
async def readiness(request: Request):
    try:
        async with request.app.state.db_pool.acquire() as connection:
            await connection.fetchval("SELECT 1")
        await request.app.state.redis.ping()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={"status": "not_ready", "reason": type(exc).__name__},
        ) from exc
    return {"status": "ready", "dependencies": {"postgres": "ok", "redis": "ok"}}
