-- Repair legacy schema drift for Postgres.
-- Idempotent: safe to run even if the schema is already correct.

-- Users: ensure auth columns exist.
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS password_salt TEXT;
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

-- Backfill username for legacy rows.
UPDATE users
SET username = COALESCE(NULLIF(username, ''), external_id, email)
WHERE username IS NULL OR username = '';

-- Deduplicate usernames before adding a unique index.
WITH d AS (
  SELECT username
  FROM users
  WHERE username IS NOT NULL AND username <> ''
  GROUP BY username
  HAVING COUNT(1) > 1
)
UPDATE users u
SET username = u.username || ' (' || u.id || ')'
FROM d
WHERE u.username = d.username;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique ON users(username) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email) WHERE email IS NOT NULL;

-- Coerce legacy users columns to expected Postgres types.
DO $$
DECLARE
    coltype text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'users'
    ) THEN
        SELECT data_type
        INTO coltype
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
          AND column_name = 'is_active';

        IF coltype IS NOT NULL AND coltype <> 'boolean' THEN
            EXECUTE 'ALTER TABLE users ALTER COLUMN is_active DROP DEFAULT';
            IF coltype IN ('smallint','integer','bigint') THEN
                EXECUTE 'ALTER TABLE users ALTER COLUMN is_active TYPE BOOLEAN USING (is_active <> 0)';
            ELSE
                EXECUTE 'ALTER TABLE users ALTER COLUMN is_active TYPE BOOLEAN USING (LOWER(is_active::text) IN (''1'',''t'',''true'',''yes'',''y''))';
            END IF;
        END IF;
        EXECUTE 'ALTER TABLE users ALTER COLUMN is_active SET DEFAULT TRUE';

        SELECT data_type
        INTO coltype
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
          AND column_name = 'locked_until';

        IF coltype IS NOT NULL AND coltype <> 'timestamp with time zone' THEN
            EXECUTE 'ALTER TABLE users ALTER COLUMN locked_until TYPE TIMESTAMPTZ USING NULLIF(locked_until::text, '''')::timestamptz';
        END IF;
    END IF;
END$$;

-- Provider keys: ensure provider CHECK allows tavily (constraint name may vary).
DO $$
DECLARE
    c record;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tenant_provider_keys'
    ) THEN
        FOR c IN
            SELECT conname
            FROM pg_constraint
            WHERE conrelid = 'public.tenant_provider_keys'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) ILIKE '%provider%'
              AND pg_get_constraintdef(oid) ILIKE '%IN%'
        LOOP
            EXECUTE format('ALTER TABLE tenant_provider_keys DROP CONSTRAINT %I', c.conname);
        END LOOP;

        ALTER TABLE tenant_provider_keys
        ADD CONSTRAINT tenant_provider_keys_provider_check
        CHECK (provider IN ('gemini','openai','groq','anthropic','tavily'));
    END IF;
END$$;

-- Invite tokens: ensure timestamp columns are TIMESTAMPTZ for Postgres operations.
DO $$
DECLARE
    coltype text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'invite_tokens'
    ) THEN
        SELECT data_type
        INTO coltype
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'invite_tokens'
          AND column_name = 'expires_at';
        IF coltype IS NOT NULL AND coltype <> 'timestamp with time zone' THEN
            EXECUTE 'ALTER TABLE invite_tokens ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING NULLIF(expires_at::text, '''')::timestamptz';
        END IF;

        SELECT data_type
        INTO coltype
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'invite_tokens'
          AND column_name = 'used_at';
        IF coltype IS NOT NULL AND coltype <> 'timestamp with time zone' THEN
            EXECUTE 'ALTER TABLE invite_tokens ALTER COLUMN used_at TYPE TIMESTAMPTZ USING NULLIF(used_at::text, '''')::timestamptz';
        END IF;

        SELECT data_type
        INTO coltype
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'invite_tokens'
          AND column_name = 'created_at';
        IF coltype IS NOT NULL AND coltype <> 'timestamp with time zone' THEN
            EXECUTE 'ALTER TABLE invite_tokens ALTER COLUMN created_at TYPE TIMESTAMPTZ USING NULLIF(created_at::text, '''')::timestamptz';
        END IF;
    END IF;
END$$;

-- Tenants: ensure is_personal exists, is boolean, and default is consistent.
DO $$
DECLARE
    coltype text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tenants'
    ) THEN
        SELECT data_type
        INTO coltype
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'tenants'
          AND column_name = 'is_personal';

        IF coltype IS NULL THEN
            EXECUTE 'ALTER TABLE tenants ADD COLUMN is_personal BOOLEAN NOT NULL DEFAULT FALSE';
        ELSIF coltype <> 'boolean' THEN
            EXECUTE 'ALTER TABLE tenants ALTER COLUMN is_personal DROP DEFAULT';
            IF coltype IN ('smallint','integer','bigint') THEN
                EXECUTE 'ALTER TABLE tenants ALTER COLUMN is_personal TYPE BOOLEAN USING (is_personal <> 0)';
            ELSE
                EXECUTE 'ALTER TABLE tenants ALTER COLUMN is_personal TYPE BOOLEAN USING (LOWER(is_personal::text) IN (''1'',''t'',''true'',''yes'',''y''))';
            END IF;
        END IF;

        EXECUTE 'ALTER TABLE tenants ALTER COLUMN is_personal SET DEFAULT FALSE';
    END IF;
END$$;

-- Memberships: ensure role constraint allows platform and product roles.
DO $$
DECLARE
    c record;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'memberships'
    ) THEN
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

-- Tenant limits: ensure token limit + boolean enabled.
ALTER TABLE IF EXISTS tenant_limits
ADD COLUMN IF NOT EXISTS daily_token_limit INTEGER NOT NULL DEFAULT 200000;

DO $$
DECLARE
    enabled_type text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tenant_limits'
    ) THEN
        SELECT data_type
        INTO enabled_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'tenant_limits'
          AND column_name = 'enabled';

        IF enabled_type IS NOT NULL AND enabled_type <> 'boolean' THEN
            EXECUTE 'ALTER TABLE tenant_limits ALTER COLUMN enabled DROP DEFAULT';
            EXECUTE 'ALTER TABLE tenant_limits ALTER COLUMN enabled TYPE BOOLEAN USING (enabled <> 0)';
        END IF;

        EXECUTE 'ALTER TABLE tenant_limits ALTER COLUMN enabled SET DEFAULT TRUE';
    END IF;
END$$;

-- Tenant usage: ensure token_count + updated_at defaults/types.
ALTER TABLE IF EXISTS tenant_usage_daily
ADD COLUMN IF NOT EXISTS token_count INTEGER NOT NULL DEFAULT 0;

DO $$
DECLARE
    updated_type text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tenant_usage_daily'
    ) THEN
        SELECT data_type
        INTO updated_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'tenant_usage_daily'
          AND column_name = 'updated_at';

        IF updated_type IS NULL THEN
            EXECUTE 'ALTER TABLE tenant_usage_daily ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()';
        ELSIF updated_type <> 'timestamp with time zone' THEN
            -- Repair empty strings before type conversion.
            EXECUTE 'UPDATE tenant_usage_daily SET updated_at = NOW()::text WHERE TRIM(COALESCE(updated_at::text, '''')) = ''''';
            EXECUTE 'ALTER TABLE tenant_usage_daily ALTER COLUMN updated_at DROP DEFAULT';
            EXECUTE 'ALTER TABLE tenant_usage_daily ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING NULLIF(updated_at::text, '''')::timestamptz';
            EXECUTE 'ALTER TABLE tenant_usage_daily ALTER COLUMN updated_at SET DEFAULT NOW()';
        END IF;
    END IF;
END$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tenant_usage_daily'
    ) THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_usage_tenant_day ON tenant_usage_daily(tenant_id, day)';
    END IF;
END$$;

-- Jobs: ensure timestamps are usable with ORM defaults.
DO $$
DECLARE
    created_type text;
    updated_type text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'jobs'
    ) THEN
        SELECT data_type
        INTO created_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'jobs'
          AND column_name = 'created_at';

        IF created_type IS NOT NULL AND created_type <> 'timestamp with time zone' THEN
            EXECUTE 'UPDATE jobs SET created_at = NOW()::text WHERE TRIM(COALESCE(created_at::text, '''')) = ''''';
            EXECUTE 'ALTER TABLE jobs ALTER COLUMN created_at DROP DEFAULT';
            EXECUTE 'ALTER TABLE jobs ALTER COLUMN created_at TYPE TIMESTAMPTZ USING NULLIF(created_at::text, '''')::timestamptz';
        END IF;
        IF created_type IS NULL THEN
            EXECUTE 'ALTER TABLE jobs ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()';
        ELSE
            EXECUTE 'ALTER TABLE jobs ALTER COLUMN created_at SET DEFAULT NOW()';
        END IF;

        SELECT data_type
        INTO updated_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'jobs'
          AND column_name = 'updated_at';

        IF updated_type IS NOT NULL AND updated_type <> 'timestamp with time zone' THEN
            EXECUTE 'UPDATE jobs SET updated_at = NOW()::text WHERE TRIM(COALESCE(updated_at::text, '''')) = ''''';
            EXECUTE 'ALTER TABLE jobs ALTER COLUMN updated_at DROP DEFAULT';
            EXECUTE 'ALTER TABLE jobs ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING NULLIF(updated_at::text, '''')::timestamptz';
        END IF;
        IF updated_type IS NULL THEN
            EXECUTE 'ALTER TABLE jobs ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()';
        ELSE
            EXECUTE 'ALTER TABLE jobs ALTER COLUMN updated_at SET DEFAULT NOW()';
        END IF;
    END IF;
END$$;

-- Tenant policy settings: coerce legacy integer booleans to boolean.
DO $$
DECLARE
    coltype text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tenant_policy_settings'
    ) THEN
        SELECT data_type
        INTO coltype
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'tenant_policy_settings'
          AND column_name = 'store_original_prompt';

        IF coltype IS NOT NULL AND coltype <> 'boolean' THEN
            EXECUTE 'ALTER TABLE tenant_policy_settings ALTER COLUMN store_original_prompt DROP DEFAULT';
            EXECUTE 'ALTER TABLE tenant_policy_settings ALTER COLUMN store_original_prompt TYPE BOOLEAN USING (store_original_prompt <> 0)';
        END IF;
        EXECUTE 'ALTER TABLE tenant_policy_settings ALTER COLUMN store_original_prompt SET DEFAULT TRUE';

        SELECT data_type
        INTO coltype
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'tenant_policy_settings'
          AND column_name = 'show_sanitized_prompt_admin';

        IF coltype IS NOT NULL AND coltype <> 'boolean' THEN
            EXECUTE 'ALTER TABLE tenant_policy_settings ALTER COLUMN show_sanitized_prompt_admin DROP DEFAULT';
            EXECUTE 'ALTER TABLE tenant_policy_settings ALTER COLUMN show_sanitized_prompt_admin TYPE BOOLEAN USING (show_sanitized_prompt_admin <> 0)';
        END IF;
        EXECUTE 'ALTER TABLE tenant_policy_settings ALTER COLUMN show_sanitized_prompt_admin SET DEFAULT TRUE';
    END IF;
END$$;
