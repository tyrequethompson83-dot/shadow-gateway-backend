-- Rebuild tenant_provider_keys to allow the 'tavily' provider.
CREATE TABLE IF NOT EXISTS tenant_provider_keys_new (
  id SERIAL PRIMARY KEY,
  tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK(provider IN ('gemini','openai','groq','anthropic','tavily')),
  api_key_enc TEXT NOT NULL,
  api_key_tail TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, provider)
);

INSERT INTO tenant_provider_keys_new (id, tenant_id, provider, api_key_enc, api_key_tail, created_at, updated_at)
SELECT id, tenant_id, provider, api_key_enc, api_key_tail, created_at, updated_at
FROM tenant_provider_keys;

DROP TABLE tenant_provider_keys;
ALTER TABLE tenant_provider_keys_new RENAME TO tenant_provider_keys;

CREATE INDEX IF NOT EXISTS idx_provider_keys_tenant ON tenant_provider_keys(tenant_id);
