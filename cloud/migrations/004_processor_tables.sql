-- Metadata tables consumed from Redis Streams (Architecture §14).
CREATE TABLE IF NOT EXISTS security_summaries (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    count INTEGER NOT NULL,
    distinct_principals INTEGER NOT NULL,
    principals TEXT[] NOT NULL DEFAULT '{}',
    sources TEXT[] NOT NULL DEFAULT '{}',
    risk_score INTEGER NOT NULL,
    event_ts TIMESTAMPTZ NOT NULL,
    payload_id UUID NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    rule TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'threshold',
    severity TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_ts TIMESTAMPTZ NOT NULL,
    last_ts TIMESTAMPTZ NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    incident_id UUID
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_open
    ON alerts(tenant_id, fingerprint) WHERE status='open';

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['security_summaries','alerts'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
            t
        );
    END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON security_summaries, alerts TO veilops_app;
GRANT USAGE, SELECT ON SEQUENCE security_summaries_id_seq TO veilops_app;
