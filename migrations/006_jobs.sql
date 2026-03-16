-- Async jobs table for exports/reports.

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  tenant_id INTEGER NOT NULL,
  user_id INTEGER,
  type TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','running','done','failed')),
  input_json TEXT,
  output_path TEXT,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_tenant_created
ON jobs(tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_jobs_status_created
ON jobs(status, created_at);
