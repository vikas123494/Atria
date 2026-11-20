-- Pull-only approved remediation actions (Person C API persistence).
CREATE TABLE IF NOT EXISTS actions (
    action_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    params JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected','delivered','executed','expired')),
    requested_by TEXT NOT NULL,
    approved_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_actions_pull
    ON actions(tenant_id,collector_id,status,created_at);
ALTER TABLE actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE actions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON actions
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT,INSERT,UPDATE,DELETE ON actions TO veilops_app;
