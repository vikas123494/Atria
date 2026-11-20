-- Durable work queue for recomputing health after late event-time arrivals.
CREATE TABLE late_metric_recomputations (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    metric TEXT NOT NULL,
    event_ts TIMESTAMPTZ NOT NULL,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at TIMESTAMPTZ,
    processed_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    UNIQUE (tenant_id, entity, metric, event_ts)
);

ALTER TABLE late_metric_recomputations ENABLE ROW LEVEL SECURITY;
ALTER TABLE late_metric_recomputations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON late_metric_recomputations
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX ix_late_recompute_pending
    ON late_metric_recomputations (queued_at)
    WHERE processed_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON late_metric_recomputations TO veilops_app;
GRANT USAGE, SELECT ON SEQUENCE late_metric_recomputations_id_seq TO veilops_app;
