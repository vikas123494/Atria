-- Per-metric state is persisted so recovery hysteresis survives watchdog restarts.
CREATE TABLE health_metric_current (
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    metric TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('Excellent', 'Good', 'Fair', 'Poor')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, entity, metric),
    FOREIGN KEY (tenant_id, entity) REFERENCES entities(tenant_id, entity) ON DELETE CASCADE
);

ALTER TABLE health_metric_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE health_metric_current FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON health_metric_current
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX ix_health_metric_current_entity
    ON health_metric_current (tenant_id, entity);

GRANT SELECT, INSERT, UPDATE, DELETE ON health_metric_current TO veilops_app;
