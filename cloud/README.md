# VeilOps Cloud Core

This service is the regional, metadata-only cloud tier. It does not accept raw logs
or arbitrary free-text telemetry.

## Local configuration

Copy `.env.example` to the deployment environment's `.env` file and generate
`COLLECTOR_SECRET_ENCRYPTION_KEY` as documented in that file. The key must decode
to exactly 32 bytes. Do not commit real secrets.

The Compose file starts PostgreSQL 16, Redis 7 and the FastAPI service. SQL files
under `migrations/` are applied by the official PostgreSQL image only when the
database volume is first initialized. For a clean local schema after migration
changes, remove the local demo volume only if its data is disposable.

## Current API

- `GET /health/live`: process liveness.
- `GET /health/ready`: PostgreSQL and Redis readiness.
- `POST /v1/ingest`: HMAC-authenticated, schema-validated metadata envelope.
- `POST /v1/heartbeat`: HMAC-authenticated collector heartbeat.

The ingest API uses the §12 envelope and §13 collector headers. HMAC is calculated
over METHOD, PATH, TIMESTAMP, NONCE and the SHA-256 body digest, separated by
newline characters.

## Security note

A server cannot verify HMAC using only a one-way Argon2 hash of the HMAC key.
This implementation stores an Argon2 verifier hash and AES-GCM-encrypted key
material. The AES key is supplied through `COLLECTOR_SECRET_ENCRYPTION_KEY`;
production must use KMS/HSM-backed key management and rotation.

## Scope and verification status

The branch includes enrollment, Ed25519 receipt signing, Redis Streams processing,
dashboard JWT tenant scoping, health evaluation/watchdog, reconciliation, action
approval/pull, event-time watermark metadata, Judge Mode reporting and an optional
Caddy TLS edge proxy. This is a development implementation, not a production
certification. End-to-end collection-to-dashboard p95, offline-detection SLO and
reconciliation loss/duplicate SLO are currently reported as not instrumented.

Dashboard APIs require a JWT signed with HS256 using the configured
`DASHBOARD_JWT_SECRET`, issuer `veilops-control`, audience
`veilops-dashboard`, and claims `sub`, `tenant_id`, and `exp`.
The control-plane identity provider must issue these tokens; this service
validates them and does not implement user login or token issuance.


## Dashboard, health, reliability and actions

Dashboard endpoints are under `/api/v1` and require a verified tenant JWT.
Available read endpoints include fleet, collector detail, entity metrics and health
history, alerts, incidents, recommendations, payload receipts, audit events and SLO
samples. `POST /api/v1/slo/render-ack` records dashboard render acknowledgements.
`GET /api/v1/events` streams tenant-scoped updates using Server-Sent Events.

Collector endpoints include authenticated `GET /v1/reconcile` and
`GET /v1/actions`. Dashboard users can request actions and explicitly approve them;
collectors can only pull approved, unexpired actions. The API does not execute
remediation commands itself.

The watchdog evaluates heartbeat age and threshold bands. Threshold degradation
uses the three-of-five recent-window rule. The deterministic health engine is not
the AIOps anomaly detector; anomaly detection and topology-aware correlation remain
Person D responsibilities.

## Operational notes

Migrations are ordered SQL scripts for fresh local database initialization. Existing
volumes require an explicit migration process; the official Postgres init directory
does not rerun scripts on an initialized volume. The local Compose credentials are
demo-only and must be replaced before any shared or production deployment.


## Event-time processing and late telemetry

Metric streams maintain a per-tenant/entity/metric event-time watermark. The watermark
is the maximum observed event timestamp minus five minutes. Events older than the
current watermark are still persisted (never silently discarded) and marked
`late_arrival=true` with the watermark used for classification. This preserves
late evidence for downstream recomputation and audit. The watermark is advanced
inside the same PostgreSQL transaction as metric persistence.

## Judge Mode SLO report

`GET /api/v1/slo/judge-mode` returns a 24-hour report with sample counts and p95
latencies. It evaluates threshold-to-alert against the 15-second target. The
collection-to-dashboard (10-second), collector-offline (60-second), and
reconciliation (zero loss/duplicates) targets are explicitly reported as
not instrumented until end-to-end measurements exist. Dashboard render-ack
receipt delay is diagnostic only; it is not mislabeled as collection-to-dashboard
latency. Missing measurements never count as passing.

## TLS edge proxy

For a public deployment with DNS already pointing to the host, set
`VEILOPS_DOMAIN` and `ACME_EMAIL`, then start the optional edge profile:

```bash
docker compose -f deploy/docker-compose.yml --profile edge up --build
```

Caddy obtains and renews HTTPS certificates and reverse-proxies to the private
Cloud API container. The API's direct port remains loopback-bound. Do not expose
the demo credentials or placeholder regional endpoints publicly.

## Migration 008

The event-time watermark migration adds columns to `metric_points` and creates
the RLS-protected `event_time_watermarks` table. As with the other migrations,
it is automatically applied only when PostgreSQL initializes a fresh volume;
existing deployments need a controlled migration run.


## Separate EU regional deployment

The EU example file is a template, not a live EU endpoint. On a separate EU host,
copy `deploy/region-eu.env.example` to a protected `.env`, replace all placeholders
with region-specific secrets and a real EU DNS name, then run:

```bash
docker compose --env-file .env -p veilops-eu -f deploy/docker-compose.yml up -d --build
```

For HTTPS, add `--profile edge` after the domain points to that host and the ACME
email is configured. Use a separate EU database and Redis deployment; do not point
EU tenants at the India region's storage. The placeholder `.example` and
`.invalid` addresses must never be used as real deployment endpoints.


## Late-event recomputation worker

When a metric arrives behind the five-minute watermark, the processor persists the
metric point and inserts a durable work item in `late_metric_recomputations`.
The background worker claims pending work with row-level locking
(`FOR UPDATE SKIP LOCKED`), reruns the entity health evaluator against the
event-time-ordered metric history, and marks the work item complete. Failed jobs
are released for retry and retain a bounded error message and attempt count.
The queue is tenant-RLS protected.

## End-to-end SLO instrumentation

The dashboard must call `POST /api/v1/slo/render-ack` after rendering data and
include `sample_key`, `rendered_at`, and `source_event_ts`. The backend records
elapsed time from the source event timestamp to receipt of the render acknowledgement
as `collection_to_dashboard`. This measures the end-to-end path only when the
frontend passes the timestamp of the actual displayed source data.

The watchdog records `collector_offline_detection` when it first observes a
collector whose heartbeat age has reached the Poor/offline threshold. The
reconciliation endpoint records the number of missing sequence numbers per checked
range as `reconciliation_missing_sequences`. Duplicate collector sequence
numbers are rejected by the database unique constraint on `(collector_id, seq)`.

The Judge Mode report calculates p95 for the latency samples and p95 for the
missing-sequence count (where zero is the target). It reports insufficient data
until real samples exist; duplicate prevention is reported as a database-enforced
invariant rather than a fabricated measured rate.
