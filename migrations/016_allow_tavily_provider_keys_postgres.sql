ALTER TABLE tenant_provider_keys
DROP CONSTRAINT IF EXISTS tenant_provider_keys_provider_check;

ALTER TABLE tenant_provider_keys
ADD CONSTRAINT tenant_provider_keys_provider_check
CHECK (provider IN ('gemini','openai','groq','anthropic','tavily'));
