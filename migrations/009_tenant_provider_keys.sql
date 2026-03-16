CREATE TABLE IF NOT EXISTS tenant_provider_keys (
  id SERIAL PRIMARY KEY,
  tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK(provider IN ('gemini','openai','groq','anthropic')),
  api_key_enc TEXT NOT NULL,
  api_key_tail TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_provider_keys_tenant ON tenant_provider_keys(tenant_id);
