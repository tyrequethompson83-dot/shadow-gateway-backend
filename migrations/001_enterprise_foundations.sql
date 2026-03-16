-- Core Postgres schema foundations (aligned with enterprise/db_enterprise.py models).

-- Tenants (orgs)
CREATE TABLE IF NOT EXISTS tenants (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_personal BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_name_unique ON tenants(name);

-- Users
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  external_id TEXT UNIQUE,
  username TEXT UNIQUE,
  display_name TEXT,
  email TEXT UNIQUE,
  password_hash TEXT,
  password_salt TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Memberships (RBAC per tenant)
CREATE TABLE IF NOT EXISTS memberships (
  id SERIAL PRIMARY KEY,
  tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, user_id),
  CONSTRAINT ck_membership_role
    CHECK(role IN ('platform_admin','admin','auditor','user','tenant_admin','employee'))
);

CREATE INDEX IF NOT EXISTS idx_memberships_tenant_role ON memberships(tenant_id, role);

-- Append-only audit logs (supports chained hashes)
CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  metadata_json TEXT,
  ip TEXT,
  user_agent TEXT,
  request_id TEXT,
  prev_hash TEXT,
  row_hash TEXT,
  chain_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_chain_id ON audit_logs(tenant_id, chain_id, id);

-- Requests table (tenant-scoped)
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  ts TEXT,
  "user" TEXT,
  purpose TEXT,
  model TEXT,
  provider TEXT,
  cleaned_prompt_preview TEXT,
  prompt_original_preview TEXT,
  prompt_sent_to_ai_preview TEXT,
  detections_count INTEGER,
  entity_counts_json TEXT,
  risk_categories_json TEXT,
  risk_score INTEGER,
  risk_level TEXT,
  severity TEXT,
  decision TEXT,
  injection_detected INTEGER NOT NULL DEFAULT 0,
  tenant_id INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_requests_tenant_created ON requests(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_requests_tenant_decision ON requests(tenant_id, decision);
CREATE INDEX IF NOT EXISTS idx_requests_tenant_provider ON requests(tenant_id, provider);
