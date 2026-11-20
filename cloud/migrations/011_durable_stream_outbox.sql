-- Durable ingest dispatch and idempotent stream processing across PostgreSQL/Redis.
CREATE TABLE ingest_stream_outbox (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    payload_id UUID NOT NULL,
    seq BIGINT NOT NULL,
    payload_hash TEXT NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    UNIQUE (tenant_id,payload_id)
);
ALTER TABLE ingest_stream_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_stream_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ingest_stream_outbox
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE INDEX ix_ingest_outbox_pending ON ingest_stream_outbox(tenant_id,id)
    WHERE published_at IS NULL;

CREATE TABLE processed_stream_payloads (
    tenant_id TEXT NOT NULL,
    payload_id UUID NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,payload_id)
);
ALTER TABLE processed_stream_payloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE processed_stream_payloads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON processed_stream_payloads
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT,INSERT,UPDATE,DELETE ON ingest_stream_outbox,processed_stream_payloads TO veilops_app;
GRANT USAGE,SELECT ON SEQUENCE ingest_stream_outbox_id_seq TO veilops_app;
