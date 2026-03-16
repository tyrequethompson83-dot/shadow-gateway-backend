DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tenant_provider_keys'
    ) THEN
        ALTER TABLE tenant_provider_keys
        DROP CONSTRAINT IF EXISTS tenant_provider_keys_provider_check;

        ALTER TABLE tenant_provider_keys
        ADD CONSTRAINT tenant_provider_keys_provider_check
        CHECK (provider IN ('gemini','openai','groq','anthropic','tavily'));
    END IF;
END$$;
