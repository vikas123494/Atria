-- Runtime database role: deliberately separate from the schema owner.
-- This role cannot bypass FORCE ROW LEVEL SECURITY.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'veilops_app') THEN
        CREATE ROLE veilops_app LOGIN PASSWORD 'veilops_app_dev_only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END $$;

GRANT CONNECT ON DATABASE veilops TO veilops_app;
GRANT USAGE ON SCHEMA public TO veilops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    ingest_receipts, entities, metric_points, collector_heartbeats,
    health_current, health_transitions, thresholds, slo_samples,
    tenants, collectors
TO veilops_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO veilops_app;
