-- VeilOps Cloud Core v1. PostgreSQL 16.
-- Regional databases store metadata only. Raw logs and secrets stay in Tier 1.

CREATE TABLE tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    home_region TEXT NOT NULL CHECK (home_region IN ('in', 'eu')),
    residency_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE collectors (
    collector_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    region TEXT NOT NULL CHECK (region IN ('in', 'eu')),
    secret_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE ingest_receipts (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    payload_id UUID NOT NULL,
    collector_id TEXT NOT NULL REFERENCES collectors(collector_id),
    seq BIGINT NOT NULL CHECK (seq > 0),
    payload_hash TEXT NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, payload_id),
    CONSTRAINT uq_ingest_collector_seq UNIQUE (collector_id, seq)
);

CREATE TABLE entities (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    entity TEXT NOT NULL,
    kind TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'demo',
    collector_id TEXT NOT NULL REFERENCES collectors(collector_id),
    PRIMARY KEY (tenant_id, entity)
);

CREATE TABLE metric_points (
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    metric TEXT NOT NULL,
    event_ts TIMESTAMPTZ NOT NULL,
    source_tz TEXT NOT NULL,
    avg DOUBLE PRECISION,
    min DOUBLE PRECISION,
    max DOUBLE PRECISION,
    p95 DOUBLE PRECISION,
    count INTEGER NOT NULL CHECK (count >= 0),
    payload_id UUID NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, entity, metric, event_ts)
) PARTITION BY RANGE (event_ts);

CREATE TABLE metric_points_default PARTITION OF metric_points DEFAULT;

CREATE TABLE collector_heartbeats (
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    body JSONB NOT NULL,
    PRIMARY KEY (tenant_id, collector_id, ts)
);

CREATE TABLE health_current (
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('Excellent', 'Good', 'Fair', 'Poor')),
    score REAL,
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    since TIMESTAMPTZ NOT NULL,
    last_data_ts TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, entity)
);

CREATE TABLE health_transitions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL CHECK (to_state IN ('Excellent', 'Good', 'Fair', 'Poor')),
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE thresholds (
    tenant_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    good NUMERIC,
    fair NUMERIC,
    poor NUMERIC,
    hysteresis NUMERIC NOT NULL DEFAULT 0.10,
    PRIMARY KEY (tenant_id, metric)
);

CREATE TABLE slo_samples (
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    sample_key TEXT NOT NULL,
    event_ts TIMESTAMPTZ NOT NULL,
    observed_ts TIMESTAMPTZ NOT NULL,
    delay_ms INTEGER NOT NULL CHECK (delay_ms >= 0),
    PRIMARY KEY (tenant_id, kind, sample_key, event_ts)
);

-- FORCE RLS so even table owners are subject to tenant policies.
-- Runtime API role must be a separate non-owner role without BYPASSRLS.
DO $$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ingest_receipts', 'entities', 'metric_points',
        'collector_heartbeats', 'health_current', 'health_transitions',
        'thresholds', 'slo_samples'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
            table_name
        );
    END LOOP;
END $$;

CREATE INDEX ix_metric_points_event_ts ON metric_points (tenant_id, event_ts DESC);
CREATE INDEX ix_heartbeats_latest ON collector_heartbeats (tenant_id, collector_id, ts DESC);
CREATE INDEX ix_health_transitions_entity_time ON health_transitions (tenant_id, entity, at_utc DESC);
