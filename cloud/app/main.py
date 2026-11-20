"""VeilOps regional Cloud Core API foundation."""
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI, HTTPException, Request
from redis.asyncio import Redis

from cloud.app.settings import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    app.state.settings = settings
    app.state.db_pool = await asyncpg.create_pool(
        settings.database_url, min_size=1,
        max_size=settings.database_pool_max, command_timeout=5,
    )
    app.state.redis = Redis.from_url(
        settings.redis_url, encoding="utf-8", decode_responses=True,
        socket_connect_timeout=2, socket_timeout=2,
    )
    try:
        yield
    finally:
        await app.state.redis.aclose()
        await app.state.db_pool.close()


app = FastAPI(
    title="VeilOps Cloud Core", version="0.1.0",
    description="Metadata-only, multi-tenant regional cloud services.",
    lifespan=lifespan,
)


@app.get("/health/live", tags=["health"])
async def liveness():
    """Process liveness; independent of external services."""
    return {"status": "alive"}


@app.get("/health/ready", tags=["health"])
async def readiness(request: Request):
    """Readiness requires PostgreSQL and Redis."""
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
