-- Tenant usage and quota tables.

CREATE TABLE IF NOT EXISTS tenant_usage_daily (
  tenant_id INTEGER NOT NULL,
  day TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  blocked_count INTEGER NOT NULL DEFAULT 0,
  risk_sum INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, day),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tenant_limits (
  tenant_id INTEGER PRIMARY KEY,
  daily_requests_limit INTEGER NOT NULL,
  rpm_limit INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_usage_tenant_day
ON tenant_usage_daily(tenant_id, day);

-- Seed default limits for tenant 1 if present.
INSERT OR IGNORE INTO tenant_limits (tenant_id, daily_requests_limit, rpm_limit, enabled)
VALUES (1, 2000, 60, 1);
