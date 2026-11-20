"""Deterministic collector/entity health evaluation (Architecture §19).

AIOps anomaly detection, correlation and root-cause ranking remain Person D scope.
"""
import json
from datetime import datetime, timezone


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
        if poor is not None and value >= float(poor):
            return "Poor"
        if fair is not None and value >= float(fair):
            return "Fair"
        if good is not None and value >= float(good):
            return "Good"
    else:
        if poor is not None and value <= float(poor):
            return "Poor"
        if fair is not None and value <= float(fair):
            return "Fair"
        if good is not None and value <= float(good):
            return "Good"
    return "Excellent"


def combine_states(states: list[str]) -> str:
    return max(states, key=STATES.index) if states else "Good"


def three_of_five_state(window_states: list[str]) -> str:
    """Promote a degraded band only when at least 3 of the latest 5 windows agree."""
    recent = window_states[:5]
    for candidate in ("Poor", "Fair", "Good"):
        if recent.count(candidate) >= 3:
            return candidate
    return "Excellent"


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
            hb_state, hb_reasons = heartbeat_state(last, now)
            entities = await conn.fetch(
                "SELECT entity FROM entities WHERE tenant_id=$1 AND collector_id=$2",
                tenant_id, collector_id,
            )
            updated = 0
            for entity_row in entities:
                entity = entity_row["entity"]
                metric_rows = await conn.fetch(
                    """SELECT m.metric,m.avg,m.max,t.good,t.fair,t.poor
                       FROM metric_points m
                       LEFT JOIN thresholds t
                         ON t.tenant_id=m.tenant_id AND t.metric=m.metric
                       WHERE m.tenant_id=$1 AND m.entity=$2
                       ORDER BY m.event_ts DESC LIMIT 100""",
                    tenant_id, entity,
                )
                by_metric = {}
                for row in metric_rows:
                    by_metric.setdefault(row["metric"], []).append(row)
                metric_states = []
                reasons = list(hb_reasons)
                for metric, samples in by_metric.items():
                    thresholds = samples[0]
                    if thresholds["good"] is None and thresholds["fair"] is None and thresholds["poor"] is None:
                        continue
                    sample_states = []
                    for sample in samples[:5]:
                        value = sample["avg"] if sample["avg"] is not None else sample["max"]
                        if value is not None:
                            sample_states.append(metric_state(
                                float(value), thresholds["good"], thresholds["fair"], thresholds["poor"]
                            ))
                    band = three_of_five_state(sample_states)
                    metric_states.append(band)
                    if band != "Excellent":
                        reasons.append(f"{metric}:{band.lower()}")
                target = combine_states([hb_state, *metric_states])
                if hb_state == "Poor":
                    target = "Poor"
                previous = await conn.fetchrow(
                    "SELECT state FROM health_current WHERE tenant_id=$1 AND entity=$2 FOR UPDATE",
                    tenant_id, entity,
                )
                if previous is None:
                    old_state = None
                    await conn.execute(
                        """INSERT INTO health_current
                           (tenant_id,entity,state,reasons,since,last_data_ts)
                           VALUES($1,$2,$3,$4::jsonb,$5,$6)""",
                        tenant_id, entity, target, json.dumps(reasons), now, last,
                    )
                else:
                    old_state = previous["state"]
                    await conn.execute(
                        """UPDATE health_current SET state=$3,reasons=$4::jsonb,
                           since=CASE WHEN state<>$3 THEN $5 ELSE since END,
                           last_data_ts=COALESCE($6,last_data_ts)
                           WHERE tenant_id=$1 AND entity=$2""",
                        tenant_id, entity, target, json.dumps(reasons), now, last,
                    )
                if old_state != target:
                    await conn.execute(
                        """INSERT INTO health_transitions
                           (tenant_id,entity,from_state,to_state,reasons,at_utc)
                           VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                        tenant_id, entity, old_state, target, json.dumps(reasons), now,
                    )
                updated += 1
    return {"collector_id": collector_id, "state": hb_state, "last_heartbeat": last,
            "entities_updated": updated, "reasons": hb_reasons}


async def watchdog_loop(pool, interval_seconds: int = 5, stop_event=None):
    """Periodically reevaluate collectors; cancellation is handled by the app lifespan."""
    import asyncio
    import logging
    while stop_event is None or not stop_event.is_set():
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT DISTINCT tenant_id,collector_id FROM collectors WHERE revoked_at IS NULL"
            )
        for row in rows:
            try:
                await evaluate_collector_health(pool, row["tenant_id"], row["collector_id"])
            except Exception:
                logging.getLogger(__name__).exception("watchdog evaluation failed")
        if stop_event is None:
            await asyncio.sleep(interval_seconds)
        else:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
            except asyncio.TimeoutError:
                pass
