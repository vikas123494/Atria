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

## Scope status

Enrollment, Ed25519 receipt signing, durable stream publishing/outbox recovery,
dashboard JWT/RBAC, health processing, reconciliation, EU deployment and Judge Mode
remain subsequent implementation milestones. Do not represent them as implemented
until their code and tests are merged.

Dashboard APIs require a JWT signed with HS256 using the configured
`DASHBOARD_JWT_SECRET`, issuer `veilops-control`, audience
`veilops-dashboard`, and claims `sub`, `tenant_id`, and `exp`.
The control-plane identity provider must issue these tokens; this service
validates them and does not implement user login or token issuance.
