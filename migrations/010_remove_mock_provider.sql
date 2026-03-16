-- Guarded: tables may not exist on fresh installs if schema is managed by ORM first.
DO $$
BEGIN
  IF to_regclass('public.tenant_provider_keys') IS NOT NULL THEN
    DELETE FROM tenant_provider_keys WHERE provider = 'mock';
  END IF;

  IF to_regclass('public.tenant_provider_configs') IS NOT NULL THEN
    DELETE FROM tenant_provider_configs WHERE provider = 'mock';
  END IF;
END$$;
