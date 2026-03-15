-- One-time migration for tenant-scoped request data.
-- If this file is executed on a DB where tenant_id already exists, skip this migration.

ALTER TABLE requests ADD COLUMN tenant_id INTEGER;

UPDATE requests
SET tenant_id = 1
WHERE tenant_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_requests_tenant_created
ON requests(tenant_id, ts);
