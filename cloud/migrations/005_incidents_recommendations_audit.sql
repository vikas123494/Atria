-- Cloud API operational records and audit trail.
CREATE TABLE IF NOT EXISTS incidents (
    incident_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    summary TEXT NOT NULL DEFAULT '',
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS recommendations (
    recommendation_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    incident_id UUID,
    title TEXT NOT NULL,
    rationale TEXT NOT NULL,
    confidence REAL,
    status TEXT NOT NULL DEFAULT 'pending',
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS evidence_links (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    incident_id UUID,
    recommendation_id UUID,
    payload_id UUID,
    evidence_type TEXT NOT NULL,
    reference TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS topology_edges (
    tenant_id TEXT NOT NULL,
    source_entity TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    relation TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,source_entity,target_entity,relation)
);
CREATE TABLE IF NOT EXISTS baselines (
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    metric TEXT NOT NULL,
    median DOUBLE PRECISION,
    mad DOUBLE PRECISION,
    ewma DOUBLE PRECISION,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,entity,metric)
);

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'incidents','recommendations','evidence_links','audit_events',
        'topology_edges','baselines'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
            t
        );
    END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE,DELETE ON incidents,recommendations,evidence_links,
    audit_events,topology_edges,baselines TO veilops_app;
GRANT USAGE,SELECT ON SEQUENCE evidence_links_id_seq,audit_events_id_seq TO veilops_app;
