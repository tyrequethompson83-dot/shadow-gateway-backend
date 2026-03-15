CREATE TABLE IF NOT EXISTS tenant_provider_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  provider TEXT NOT NULL CHECK(provider IN ('gemini','openai','groq','anthropic')),
  api_key_enc TEXT NOT NULL,
  api_key_tail TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(tenant_id, provider),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_provider_keys_tenant ON tenant_provider_keys(tenant_id);
