-- Postgres migration to allow 'tavily' in tenant_provider_keys
DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT tc.constraint_name
    INTO constraint_name
    FROM information_schema.table_constraints tc
    WHERE tc.table_name = 'tenant_provider_keys'
      AND tc.constraint_type = 'CHECK'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE tenant_provider_keys DROP CONSTRAINT %I', constraint_name);
    END IF;

    ALTER TABLE tenant_provider_keys
    ADD CONSTRAINT tenant_provider_keys_provider_check
    CHECK (provider IN ('gemini','openai','groq','anthropic','tavily'));
END$$;
