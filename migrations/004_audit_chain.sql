-- One-time migration for chained audit hashes.
-- If these columns already exist, skip this file.

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS row_hash TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS chain_id TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id
ON audit_logs(tenant_id, id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_chain_id
ON audit_logs(tenant_id, chain_id, id);
