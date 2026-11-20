"""Idempotent Redis Streams consumer and PostgreSQL metadata writer."""
import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from redis.exceptions import ResponseError

log = logging.getLogger(__name__)


def calculate_event_time_watermark(previous_max: datetime | None, event_ts: datetime,
                                   allowed_lateness: timedelta = timedelta(minutes=5)):
    """Return (new_max_event_ts, watermark, is_late) for an event-time stream."""
    max_event_ts = event_ts if previous_max is None else max(previous_max, event_ts)
    watermark_ts = max_event_ts - allowed_lateness
    return max_event_ts, watermark_ts, event_ts < watermark_ts


def _dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("event_ts must be timezone-aware")
    return parsed.astimezone(timezone.utc)


class StreamProcessor:
    def __init__(self, redis, pool, stream: str, group: str = "cloud-writers",
                 consumer: str = "writer-1"):
        self.redis, self.pool = redis, pool
        self.stream, self.group, self.consumer = stream, group, consumer

    async def ensure_group(self):
        try:
            await self.redis.xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def run(self, stop: asyncio.Event):
        await self.ensure_group()
        while not stop.is_set():
            try:
                # Recover messages left pending by a crashed consumer.
                claimed = await self.redis.xautoclaim(
                    self.stream, self.group, self.consumer,
                    min_idle_time=30_000, start_id="0-0", count=25,
                )
                for message_id, fields in claimed[1]:
                    await self._handle(message_id, fields)
                batches = await self.redis.xreadgroup(
                    self.group, self.consumer, {self.stream: ">"},
                    count=50, block=1000,
                )
                for _, messages in batches:
                    for message_id, fields in messages:
                        await self._handle(message_id, fields)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Cloud stream processing cycle failed")
                await asyncio.sleep(1)

    async def _handle(self, message_id, fields):
        body = json.loads(fields["body"])
        tenant_id = fields["tenant_id"]
        collector_id = fields["collector_id"]
        payload_id = UUID(fields["payload_id"])
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                claimed = await conn.fetchval(
                    """INSERT INTO processed_stream_payloads(tenant_id,payload_id)
                       VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING payload_id""",
                    tenant_id, payload_id,
                )
                # Redis may redeliver after a crash between PG commit and XACK.
                # This ledger prevents duplicate side effects while allowing the
                # notification to be republished before the stream entry is ACKed.
                if claimed:
                    for record in body["records"]:
                        kind = record["type"]
                        event_ts = _dt(record["event_ts"])
                        if kind == "metric":
                            await self._metric(conn, tenant_id, collector_id, payload_id, record, event_ts)
                        elif kind == "security_summary":
                            await conn.execute(
                                """INSERT INTO security_summaries
                                   (tenant_id,category,severity,count,distinct_principals,
                                    principals,sources,risk_score,event_ts,payload_id)
                                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
                                tenant_id, record["category"], record["severity"], record["count"],
                                record["distinct_principals"], record["principals"], record["sources"],
                                record["risk_score"], event_ts, payload_id,
                            )
                        elif kind == "alert":
                            await self._alert(conn, tenant_id, record, event_ts)
                        elif kind == "health":
                            await self._health(conn, tenant_id, record, event_ts)
        await self.redis.publish(
            f"veilops:tenant:{tenant_id}:events",
            json.dumps({"event": "telemetry_processed", "collector_id": collector_id, "payload_id": str(payload_id)}),
        )
        await self.redis.xack(self.stream, self.group, message_id)

    async def _metric(self, conn, tenant_id, collector_id, payload_id, record, event_ts):
        await conn.execute(
            """INSERT INTO entities(tenant_id,entity,kind,collector_id)
               VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,entity) DO NOTHING""",
            tenant_id, record["entity"], record["entity_kind"], collector_id,
        )
        # Serialize watermark advancement per tenant/entity/metric. Late data is
        # retained; the flag makes it observable for reconciliation/recomputation.
        await conn.execute(
            """INSERT INTO event_time_watermarks
               (tenant_id,entity,metric,max_event_ts,watermark_ts)
               VALUES($1,$2,$3,$4,$4 - INTERVAL '5 minutes')
               ON CONFLICT(tenant_id,entity,metric) DO NOTHING""",
            tenant_id, record["entity"], record["metric"], event_ts,
        )
        watermark_row = await conn.fetchrow(
            """SELECT max_event_ts FROM event_time_watermarks
               WHERE tenant_id=$1 AND entity=$2 AND metric=$3 FOR UPDATE""",
            tenant_id, record["entity"], record["metric"],
        )
        max_event_ts, watermark_ts, is_late = calculate_event_time_watermark(
            watermark_row["max_event_ts"], event_ts
        )
        await conn.execute(
            """UPDATE event_time_watermarks
               SET max_event_ts=$4,watermark_ts=$5,updated_at=now()
               WHERE tenant_id=$1 AND entity=$2 AND metric=$3""",
            tenant_id, record["entity"], record["metric"], max_event_ts, watermark_ts,
        )
        await conn.execute(
            """INSERT INTO metric_points
               (tenant_id,entity,metric,event_ts,source_tz,avg,min,max,p95,count,payload_id,
                late_arrival,watermark_ts)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
               ON CONFLICT(tenant_id,entity,metric,event_ts) DO UPDATE
               SET avg=EXCLUDED.avg,min=EXCLUDED.min,max=EXCLUDED.max,
                   p95=EXCLUDED.p95,count=EXCLUDED.count,payload_id=EXCLUDED.payload_id,
                   late_arrival=metric_points.late_arrival OR EXCLUDED.late_arrival,
                   watermark_ts=GREATEST(metric_points.watermark_ts,EXCLUDED.watermark_ts),
                   received_at=now()
               WHERE EXCLUDED.count > metric_points.count""",
            tenant_id, record["entity"], record["metric"], event_ts, record["source_tz"],
            record.get("avg"), record.get("min"), record.get("max"), record.get("p95"),
            record["count"], payload_id, is_late, watermark_ts,
        )
        if is_late:
            await conn.execute(
                """INSERT INTO late_metric_recomputations
                   (tenant_id,entity,metric,event_ts)
                   VALUES($1,$2,$3,$4)
                   ON CONFLICT(tenant_id,entity,metric,event_ts) DO NOTHING""",
                tenant_id, record["entity"], record["metric"], event_ts,
            )
            log.info("Stored late metric event and queued health recomputation: tenant=%s entity=%s metric=%s event_ts=%s watermark=%s",
                     tenant_id, record["entity"], record["metric"], event_ts, watermark_ts)

    async def _alert(self, conn, tenant_id, record, event_ts):
        observed = datetime.now(timezone.utc)
        delay_ms = max(0, int((observed - event_ts).total_seconds() * 1000))
        await conn.execute(
            """INSERT INTO slo_samples
               (tenant_id,kind,sample_key,event_ts,observed_ts,delay_ms)
               VALUES($1,'threshold_to_alert',$2,$3,$4,$5)
               ON CONFLICT DO NOTHING""",
            tenant_id, str(record["alert_id"]), event_ts, observed, delay_ms,
        )
        fingerprint = f'{tenant_id}:{record["entity"]}:{record["rule"]}:{record["template_id"]}'
        context = json.dumps({"template_id": record["template_id"], "params": record["params"]})
        await conn.execute(
            """INSERT INTO alerts
               (alert_id,tenant_id,entity,rule,severity,fingerprint,first_ts,last_ts,context)
               VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8::jsonb)
               ON CONFLICT (tenant_id,fingerprint) WHERE status='open'
               DO UPDATE SET last_ts=GREATEST(alerts.last_ts,EXCLUDED.last_ts),
                             occurrences=alerts.occurrences+1,context=EXCLUDED.context""",
            UUID(str(record["alert_id"])), tenant_id, record["entity"], record["rule"],
            record["severity"], fingerprint, event_ts, context,
        )

    async def _health(self, conn, tenant_id, record, event_ts):
        entity = record["entity"]
        state = record["state"]
        reasons = json.dumps(record.get("reasons", []))
        previous = await conn.fetchrow(
            "SELECT state FROM health_current WHERE tenant_id=$1 AND entity=$2 FOR UPDATE",
            tenant_id, entity,
        )
        if previous is None:
            await conn.execute(
                """INSERT INTO health_current
                   (tenant_id,entity,state,score,reasons,since,last_data_ts)
                   VALUES($1,$2,$3,$4,$5::jsonb,$6,$6)""",
                tenant_id, entity, state, record.get("score"), reasons, event_ts,
            )
            old_state = None
        else:
            old_state = previous["state"]
            await conn.execute(
                """UPDATE health_current SET state=$3,score=$4,reasons=$5::jsonb,
                   since=CASE WHEN state<>$3 THEN $6 ELSE since END,last_data_ts=$6
                   WHERE tenant_id=$1 AND entity=$2""",
                tenant_id, entity, state, record.get("score"), reasons, event_ts,
            )
        if old_state != state:
            await conn.execute(
                """INSERT INTO health_transitions
                   (tenant_id,entity,from_state,to_state,reasons,at_utc)
                   VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                tenant_id, entity, old_state, state, reasons, event_ts,
            )


async def stream_outbox_publisher(redis, pool, stream: str, interval_seconds: float = 0.5,
                                  stop_event=None):
    """Publish committed ingest outbox rows to Redis Streams, safely retrying failures."""
    while stop_event is None or not stop_event.is_set():
        published = False
        row = None
        tenant_id = None
        try:
            async with pool.acquire() as conn:
                tenants = await conn.fetch("SELECT tenant_id FROM tenants ORDER BY tenant_id")
            for tenant_row in tenants:
                tenant_id = tenant_row["tenant_id"]
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                        row = await conn.fetchrow(
                            """SELECT id,collector_id,payload_id,seq,payload_hash,sent_at,
                                      received_at,body
                               FROM ingest_stream_outbox
                               WHERE tenant_id=$1 AND published_at IS NULL
                               ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1""",
                            tenant_id,
                        )
                        if row:
                            body = row["body"]
                            if not isinstance(body, str):
                                body = json.dumps(body, separators=(",", ":"))
                            await redis.xadd(
                                stream,
                                {"tenant_id": tenant_id, "collector_id": row["collector_id"],
                                 "payload_id": str(row["payload_id"]), "seq": str(row["seq"]),
                                 "payload_hash": row["payload_hash"],
                                 "sent_at": row["sent_at"].isoformat(),
                                 "received_at": row["received_at"].isoformat(), "body": body},
                                maxlen=1_000_000, approximate=True,
                            )
                            await conn.execute(
                                """UPDATE ingest_stream_outbox
                                   SET published_at=now(),attempts=attempts+1,last_error=NULL
                                   WHERE id=$1""",
                                row["id"],
                            )
                            published = True
                if published:
                    break
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("ingest outbox publisher failed")
            try:
                if row:
                    async with pool.acquire() as conn:
                        async with conn.transaction():
                            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                            await conn.execute(
                                """UPDATE ingest_stream_outbox
                                   SET attempts=attempts+1,last_error=$2 WHERE id=$1""",
                                row["id"], str(exc)[:1000],
                            )
            except Exception:
                log.exception("could not record ingest outbox publisher failure")
        if not published:
            if stop_event is None:
                await asyncio.sleep(interval_seconds)
            else:
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
                except asyncio.TimeoutError:
                    pass
