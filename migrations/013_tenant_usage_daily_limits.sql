-- Ensure per-tenant daily usage table and index exist for quota/rate-limit enforcement.
-- token_count is included for optional token-based daily caps.

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

CREATE INDEX IF NOT EXISTS idx_usage_tenant_day
ON tenant_usage_daily(tenant_id, day);
