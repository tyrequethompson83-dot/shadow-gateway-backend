DO $$
BEGIN
  IF to_regclass('public.tenant_provider_configs') IS NOT NULL THEN
    UPDATE tenant_provider_configs
    SET model = 'llama-3.1-8b-instant',
        updated_at = NOW()
    WHERE provider = 'groq'
      AND COALESCE(TRIM(model), '') NOT IN ('llama-3.1-8b-instant', 'llama-3.3-70b-versatile');
  END IF;
END$$;
