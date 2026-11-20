-- Event-time watermarking: keep five minutes of allowed lateness per metric stream.
ALTER TABLE metric_points
    ADD COLUMN late_arrival BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN watermark_ts TIMESTAMPTZ;

CREATE TABLE event_time_watermarks (
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    metric TEXT NOT NULL,
    max_event_ts TIMESTAMPTZ NOT NULL,
    watermark_ts TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, entity, metric),
    FOREIGN KEY (tenant_id, entity) REFERENCES entities(tenant_id, entity) ON DELETE CASCADE
);

ALTER TABLE event_time_watermarks ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_time_watermarks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON event_time_watermarks
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX ix_metric_points_late
    ON metric_points (tenant_id, entity, metric, event_ts DESC)
    WHERE late_arrival = TRUE;

GRANT SELECT, INSERT, UPDATE, DELETE ON event_time_watermarks TO veilops_app;
