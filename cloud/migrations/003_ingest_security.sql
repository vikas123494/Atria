-- Regional ingest security and enrollment support.
-- HMAC verification needs recoverable key material; Argon2 hashes cannot verify HMAC.
-- Store the per-collector key encrypted with an application/KMS-managed AES-GCM key.
ALTER TABLE collectors ADD COLUMN IF NOT EXISTS secret_ciphertext BYTEA;

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    region TEXT NOT NULL CHECK (region IN ('in','eu')),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS collector_seq_state (
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    highest_contiguous_seq BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, collector_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_tokens, collector_seq_state TO veilops_app;
