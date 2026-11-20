"""Deterministic collector/entity health evaluation (Architecture §19).

AIOps anomaly detection, correlation and root-cause ranking remain Person D scope.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone

STATES = ("Excellent", "Good", "Fair", "Poor")

# Section 19 default bands. Tenant-specific rows in thresholds override these.
DEFAULT_THRESHOLDS = {
    "cpu.util_pct": (60.0, 75.0, 90.0),
    "mem.util_pct": (70.0, 80.0, 92.0),
    "memory.util_pct": (70.0, 80.0, 92.0),
    "disk.util_pct": (70.0, 85.0, 95.0),
    "net.loss_pct": (0.5, 2.0, 5.0),
    "network.packet_loss_pct": (0.5, 2.0, 5.0),
    "security.risk_score": (20.0, 50.0, 80.0),
}


def heartbeat_state(last_seen: datetime | None, now: datetime | None = None) -> tuple[str, list[str]]:
    now = now or datetime.now(timezone.utc)
    if last_seen is None:
        return "Poor", ["no_heartbeat_received"]
    age = max(0.0, (now - last_seen).total_seconds())
    if age > 30:
        return "Poor", ["heartbeat_missing_over_30s"]
    if age >= 15:
        return "Fair", ["heartbeat_missing_15s"]
    if age >= 10:
        return "Good", ["heartbeat_delayed_10s"]
    return "Excellent", ["heartbeat_recent"]


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
    """Return a degraded state only when it appears in at least 3 of 5 windows."""
    recent = window_states[:5]
    for candidate in ("Poor", "Fair", "Good"):
        if recent.count(candidate) >= 3:
            return candidate
    return "Excellent"


def recovered_inside_margin(values: list[float], target: str, good, fair, poor,
                             margin: float = 0.10) -> bool:
    """Require 3 consecutive samples 10% inside the boundary for an improved state."""
    if len(values) < 3:
        return False
    boundary = {"Excellent": good, "Good": fair, "Fair": poor}.get(target)
    if boundary is None:
        return target == "Poor"
    boundary = float(boundary)
    # VeilOps' configured metric thresholds use higher-is-worse semantics.
    return all(value <= boundary * (1.0 - margin) for value in values[:3])


def cap_for_stale_metrics(state: str, last_metric_ts: datetime | None,
                          now: datetime) -> tuple[str, list[str]]:
    """Stale metric data may not look healthier than the architecture permits."""
    if last_metric_ts is None:
        return "Fair" if STATES.index(state) < STATES.index("Fair") else state, ["no_metric_data"]
    age = max(0.0, (now - last_metric_ts).total_seconds())
    if age > 30:
        return ("Fair" if STATES.index(state) < STATES.index("Fair") else state,
                ["metric_data_stale_30s"])
    if age > 15:
        return ("Good" if STATES.index(state) < STATES.index("Good") else state,
                ["metric_data_stale_15s"])
    return state, []


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
            if hb_state == "Poor" and last is not None:
                offline_delay_ms = max(0, int((now - last).total_seconds() * 1000))
                await conn.execute(
                    """INSERT INTO slo_samples
                       (tenant_id,kind,sample_key,event_ts,observed_ts,delay_ms)
                       VALUES($1,'collector_offline_detection',$2,$3,$4,$5)
                       ON CONFLICT DO NOTHING""",
                    tenant_id, collector_id, last, now, offline_delay_ms,
                )
            entities = await conn.fetch(
                "SELECT entity FROM entities WHERE tenant_id=$1 AND collector_id=$2",
                tenant_id, collector_id,
            )
            updated = 0
            for entity_row in entities:
                entity = entity_row["entity"]
                metric_rows = await conn.fetch(
                    """SELECT m.metric,m.avg,m.max,m.event_ts,t.good,t.fair,t.poor,t.hysteresis
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
                latest_metric_ts = max((r["event_ts"] for r in metric_rows), default=None)

                for metric, samples in by_metric.items():
                    thresholds = samples[0]
                    good, fair, poor = thresholds["good"], thresholds["fair"], thresholds["poor"]
                    if good is None and fair is None and poor is None:
                        good, fair, poor = DEFAULT_THRESHOLDS.get(metric, (None, None, None))
                    hysteresis = float(thresholds["hysteresis"] if thresholds["hysteresis"] is not None else 0.10)
                    if good is None and fair is None and poor is None:
                        continue
                    values = [
                        float(row["avg"] if row["avg"] is not None else row["max"])
                        for row in samples
                        if row["avg"] is not None or row["max"] is not None
                    ]
                    sample_states = [
                        metric_state(value, good, fair, poor) for value in values[:5]
                    ]
                    candidate = three_of_five_state(sample_states)
                    prior = await conn.fetchrow(
                        """SELECT state FROM health_metric_current
                           WHERE tenant_id=$1 AND entity=$2 AND metric=$3 FOR UPDATE""",
                        tenant_id, entity, metric,
                    )
                    previous_metric_state = prior["state"] if prior else None
                    if (previous_metric_state is not None
                            and STATES.index(candidate) < STATES.index(previous_metric_state)
                            and not recovered_inside_margin(values, candidate, good, fair, poor, hysteresis)):
                        candidate = previous_metric_state
                        reasons.append(f"{metric}:recovery_hysteresis_pending")
                    await conn.execute(
                        """INSERT INTO health_metric_current
                           (tenant_id,entity,metric,state,updated_at)
                           VALUES($1,$2,$3,$4,$5)
                           ON CONFLICT(tenant_id,entity,metric) DO UPDATE
                           SET state=EXCLUDED.state,updated_at=EXCLUDED.updated_at""",
                        tenant_id, entity, metric, candidate, now,
                    )
                    metric_states.append(candidate)
                    if candidate != "Excellent":
                        reasons.append(f"{metric}:{candidate.lower()}")

                target = combine_states([hb_state, *metric_states])
                target, stale_reasons = cap_for_stale_metrics(target, latest_metric_ts, now)
                reasons.extend(stale_reasons)
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
                        tenant_id, entity, target, json.dumps(reasons), now, latest_metric_ts,
                    )
                else:
                    old_state = previous["state"]
                    await conn.execute(
                        """UPDATE health_current SET state=$3,reasons=$4::jsonb,
                           since=CASE WHEN state<>$3 THEN $5 ELSE since END,
                           last_data_ts=COALESCE($6,last_data_ts)
                           WHERE tenant_id=$1 AND entity=$2""",
                        tenant_id, entity, target, json.dumps(reasons), now, latest_metric_ts,
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


async def late_metric_recompute_loop(pool, interval_seconds: int = 2, stop_event=None):
    """Re-evaluate an entity after late telemetry is durably queued.

    The normal health evaluator reads the newest event-time ordered samples,
    so rerunning it after a late insert recomputes the affected health state
    using the corrected event-time history.
    """
    while stop_event is None or not stop_event.is_set():
        item = None
        try:
            # tenants is global control-plane metadata; set tenant context before
            # reading or claiming any RLS-protected queue/entity rows.
            async with pool.acquire() as conn:
                tenant_ids = await conn.fetch("SELECT tenant_id FROM tenants ORDER BY tenant_id")
            for tenant_row in tenant_ids:
                tenant_id = tenant_row["tenant_id"]
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                        item = await conn.fetchrow(
                            """SELECT q.id,q.tenant_id,q.entity,e.collector_id
                               FROM late_metric_recomputations q
                               JOIN entities e
                                 ON e.tenant_id=q.tenant_id AND e.entity=q.entity
                               WHERE q.tenant_id=$1 AND q.processed_at IS NULL
                                 AND (q.claimed_at IS NULL OR q.claimed_at < now() - INTERVAL '2 minutes')
                               ORDER BY q.queued_at
                               LIMIT 1 FOR UPDATE OF q SKIP LOCKED""",
                            tenant_id,
                        )
                        if item:
                            await conn.execute(
                                """UPDATE late_metric_recomputations
                                   SET claimed_at=now(),attempts=attempts+1,last_error=NULL
                                   WHERE id=$1""",
                                item["id"],
                            )
                if item:
                    break
            if item:
                await evaluate_collector_health(
                    pool, item["tenant_id"], item["collector_id"]
                )
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        await conn.execute(
                            "SELECT set_config('app.tenant_id',$1,true)", item["tenant_id"]
                        )
                        await conn.execute(
                            """UPDATE late_metric_recomputations
                               SET processed_at=now(),claimed_at=NULL,last_error=NULL
                               WHERE id=$1""",
                            item["id"],
                        )
            else:
                if stop_event is None:
                    await asyncio.sleep(interval_seconds)
                else:
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
                    except asyncio.TimeoutError:
                        pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logging.getLogger(__name__).exception("late metric recomputation failed")
            if item:
                try:
                    async with pool.acquire() as conn:
                        async with conn.transaction():
                            await conn.execute(
                                "SELECT set_config('app.tenant_id',$1,true)", item["tenant_id"]
                            )
                            await conn.execute(
                                """UPDATE late_metric_recomputations
                                   SET claimed_at=NULL,last_error=$2
                                   WHERE id=$1""",
                                item["id"], str(exc)[:1000],
                            )
                except Exception:
                    logging.getLogger(__name__).exception("could not release recompute claim")
            await asyncio.sleep(interval_seconds)
