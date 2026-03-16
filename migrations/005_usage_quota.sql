-- Tenant usage and quota tables.

CREATE TABLE IF NOT EXISTS tenant_usage_daily (
  tenant_id INTEGER NOT NULL,
  day TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  token_count INTEGER NOT NULL DEFAULT 0,
  blocked_count INTEGER NOT NULL DEFAULT 0,
  risk_sum INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, day),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tenant_limits (
  tenant_id INTEGER PRIMARY KEY,
  daily_requests_limit INTEGER NOT NULL,
  rpm_limit INTEGER NOT NULL,
  daily_token_limit INTEGER NOT NULL DEFAULT 200000,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- If tenant_limits was created earlier by the ORM, it may be missing a server-side default for
-- daily_token_limit. Ensure the default exists and backfill any NULLs before enforcing NOT NULL.
ALTER TABLE IF EXISTS tenant_limits
  ADD COLUMN IF NOT EXISTS daily_token_limit INTEGER;

ALTER TABLE IF EXISTS tenant_limits
  ALTER COLUMN daily_token_limit SET DEFAULT 200000;

UPDATE tenant_limits
SET daily_token_limit = 200000
WHERE daily_token_limit IS NULL;

ALTER TABLE IF EXISTS tenant_limits
  ALTER COLUMN daily_token_limit SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_usage_tenant_day
ON tenant_usage_daily(tenant_id, day);

-- Seed default limits for tenant 1 if present.
INSERT INTO tenant_limits (tenant_id, daily_requests_limit, rpm_limit, daily_token_limit, enabled)
VALUES (1, 2000, 60, 200000, true)
ON CONFLICT (tenant_id) DO NOTHING;
