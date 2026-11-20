"""Cloud-side collector/entity health evaluation (Architecture §19).

AIOps anomaly detection and correlation remain owned by Person D.
This module implements deterministic health state and transition persistence.
"""
from datetime import datetime, timedelta, timezone


STATES = ("Excellent", "Good", "Fair", "Poor")


def heartbeat_state(last_seen: datetime | None, now: datetime | None = None) -> tuple[str, list[str]]:
    now = now or datetime.now(timezone.utc)
    if last_seen is None:
        return "Poor", ["no_heartbeat_received"]
    age = max(0.0, (now - last_seen).total_seconds())
    if age >= 30:
        return "Poor", ["heartbeat_missing_30s"]
    if age >= 15:
        return "Fair", ["heartbeat_missing_15s"]
    return "Good", ["heartbeat_recent"]


def metric_state(value: float, good: float | None, fair: float | None,
                 poor: float | None, *, higher_is_worse: bool = True) -> str:
    if higher_is_worse:
        if poor is not None and value >= poor:
            return "Poor"
        if fair is not None and value >= fair:
            return "Fair"
        if good is not None and value >= good:
            return "Good"
    else:
        if poor is not None and value <= poor:
            return "Poor"
        if fair is not None and value <= fair:
            return "Fair"
        if good is not None and value <= good:
            return "Good"
    return "Excellent"


def combine_states(states: list[str]) -> str:
    if not states:
        return "Good"
    return max(states, key=STATES.index)


async def evaluate_collector_health(pool, tenant_id: str, collector_id: str,
                                    now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
            last = await conn.fetchval(
                """SELECT max(ts) FROM collector_heartbeats
                   WHERE tenant_id=$1 AND collector_id=$2""",
                tenant_id, collector_id,
            )
            state, reasons = heartbeat_state(last, now)
            entities = await conn.fetch(
                "SELECT entity FROM entities WHERE tenant_id=$1 AND collector_id=$2",
                tenant_id, collector_id,
            )
            for row in entities:
                entity = row["entity"]
                previous = await conn.fetchrow(
                    "SELECT state,since FROM health_current WHERE tenant_id=$1 AND entity=$2 FOR UPDATE",
                    tenant_id, entity,
                )
                # Offline collectors force all their entities to Poor.
                target = "Poor" if state == "Poor" else state
                if previous is None:
                    await conn.execute(
                        """INSERT INTO health_current
                           (tenant_id,entity,state,reasons,since,last_data_ts)
                           VALUES($1,$2,$3,$4::jsonb,$5,$6)""",
                        tenant_id, entity, target, __import__("json").dumps(reasons),
                        now, last,
                    )
                    old = None
                else:
                    old = previous["state"]
                    # Staleness caps: >15s at most Good, >30s at most Fair;
                    # a fully offline collector is Poor.
                    await conn.execute(
                        """UPDATE health_current SET state=$3,reasons=$4::jsonb,
                           since=CASE WHEN state<>$3 THEN $5 ELSE since END,
                           last_data_ts=COALESCE($6,last_data_ts)
                           WHERE tenant_id=$1 AND entity=$2""",
                        tenant_id, entity, target, __import__("json").dumps(reasons), now, last,
                    )
                if old != target:
                    await conn.execute(
                        """INSERT INTO health_transitions
                           (tenant_id,entity,from_state,to_state,reasons,at_utc)
                           VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                        tenant_id, entity, old, target, __import__("json").dumps(reasons), now,
                    )
    return {"collector_id": collector_id, "state": state, "last_heartbeat": last,
            "entities_updated": len(entities), "reasons": reasons}


async def watchdog_loop(pool, interval_seconds: int = 5, stop_event=None):
    """Periodically reevaluate every tenant/collector heartbeat."""
    import asyncio
    while stop_event is None or not stop_event.is_set():
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT DISTINCT tenant_id,collector_id FROM collectors
                   WHERE revoked_at IS NULL"""
            )
        for row in rows:
            try:
                await evaluate_collector_health(pool, row["tenant_id"], row["collector_id"])
            except Exception:
                import logging
                logging.getLogger(__name__).exception("watchdog evaluation failed")
        if stop_event is None:
            await asyncio.sleep(interval_seconds)
        else:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
            except asyncio.TimeoutError:
                pass
