-- Architecture alignment: tenant memberships, threshold administration and action results.
CREATE TABLE IF NOT EXISTS memberships (
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('viewer','operator','approver','tenant_admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON memberships TO veilops_app;

ALTER TABLE actions ADD COLUMN IF NOT EXISTS policy_ref TEXT;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS result JSONB;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ;
ALTER TABLE actions DROP CONSTRAINT IF EXISTS actions_status_check;
ALTER TABLE actions ADD CONSTRAINT actions_status_check
    CHECK (status IN ('pending','approved','rejected','delivered','executed','expired','dry_run_ok','rolled_back','vetoed'));

-- Threshold configuration is tenant-admin managed; defaults remain application/config seeded.
ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
