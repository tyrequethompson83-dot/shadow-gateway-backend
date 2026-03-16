-- Product authentication and onboarding schema additions.
-- Postgres-safe and idempotent (no table drops).

ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_personal BOOLEAN NOT NULL DEFAULT FALSE;

-- Ensure memberships.role constraint allows product roles + platform roles.
DO $$
DECLARE
    c record;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'memberships'
    ) THEN
        -- Drop any existing role CHECK constraints (name may vary by origin).
        FOR c IN
            SELECT conname
            FROM pg_constraint
            WHERE conrelid = 'public.memberships'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) ILIKE '%role%'
              AND pg_get_constraintdef(oid) ILIKE '%IN%'
        LOOP
            EXECUTE format('ALTER TABLE memberships DROP CONSTRAINT %I', c.conname);
        END LOOP;

        ALTER TABLE memberships
        ADD CONSTRAINT ck_membership_role
        CHECK (role IN ('platform_admin','admin','auditor','user','tenant_admin','employee'));
    END IF;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_memberships_tenant_user ON memberships(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_tenant_role ON memberships(tenant_id, role);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_name_unique ON tenants(name);

CREATE TABLE IF NOT EXISTS invite_tokens (
  id SERIAL PRIMARY KEY,
  tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  email TEXT,
  role TEXT NOT NULL CHECK(role IN ('tenant_admin','employee')),
  expires_at TIMESTAMPTZ NOT NULL,
  max_uses INTEGER,
  uses_count INTEGER NOT NULL DEFAULT 0,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invite_tokens_tenant ON invite_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invite_tokens_token ON invite_tokens(token);
