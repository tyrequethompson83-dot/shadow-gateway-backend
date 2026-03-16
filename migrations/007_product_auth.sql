-- Product authentication and onboarding schema additions.
-- This is equivalent to the additive migration logic in product_auth.ensure_product_auth_schema().

ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_personal BOOLEAN NOT NULL DEFAULT TRUE;

-- Recreate memberships with expanded role support.
CREATE TABLE IF NOT EXISTS memberships_v2 (
  id SERIAL PRIMARY KEY,
  tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('admin','auditor','user','tenant_admin','employee')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, user_id)
);

INSERT INTO memberships_v2 (id, tenant_id, user_id, role, created_at)
SELECT id, tenant_id, user_id, role, created_at
FROM memberships;

DROP TABLE memberships;
ALTER TABLE memberships_v2 RENAME TO memberships;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_name_unique ON tenants(name);
CREATE INDEX IF NOT EXISTS idx_memberships_tenant_role ON memberships(tenant_id, role);

CREATE TABLE IF NOT EXISTS invite_tokens (
  id SERIAL PRIMARY KEY,
  tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  email TEXT,
  role TEXT NOT NULL CHECK(role IN ('tenant_admin','employee')),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invite_tokens_tenant ON invite_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invite_tokens_token ON invite_tokens(token);
