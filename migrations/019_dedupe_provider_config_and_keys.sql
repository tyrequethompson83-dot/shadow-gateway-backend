-- Repair legacy duplicates in provider config/key tables and enforce uniqueness.
-- Postgres-only (uses DO blocks, window functions, and ctid).

DO $$
BEGIN
  -- tenant_provider_configs: enforce one row per tenant_id
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'tenant_provider_configs'
  ) THEN
    -- Normalize provider values to match CHECK constraints / app expectations.
    UPDATE tenant_provider_configs
    SET provider = LOWER(TRIM(provider))
    WHERE provider IS NOT NULL;

    -- Keep the newest row per tenant_id (by updated_at/created_at) and delete the rest.
    WITH ranked AS (
      SELECT
        ctid,
        ROW_NUMBER() OVER (
          PARTITION BY tenant_id
          ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST
        ) AS rn
      FROM tenant_provider_configs
    )
    DELETE FROM tenant_provider_configs t
    USING ranked r
    WHERE t.ctid = r.ctid AND r.rn > 1;

    -- Prevent future duplicates.
    CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_provider_configs_tenant_id
      ON tenant_provider_configs(tenant_id);
  END IF;

  -- tenant_provider_keys: enforce one row per (tenant_id, provider)
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'tenant_provider_keys'
  ) THEN
    UPDATE tenant_provider_keys
    SET provider = LOWER(TRIM(provider))
    WHERE provider IS NOT NULL;

    WITH ranked AS (
      SELECT
        ctid,
        ROW_NUMBER() OVER (
          PARTITION BY tenant_id, provider
          ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
        ) AS rn
      FROM tenant_provider_keys
    )
    DELETE FROM tenant_provider_keys t
    USING ranked r
    WHERE t.ctid = r.ctid AND r.rn > 1;

    CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_provider_keys_tenant_provider
      ON tenant_provider_keys(tenant_id, provider);
  END IF;
END$$;

