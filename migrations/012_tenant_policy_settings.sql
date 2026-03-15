-- Tenant-level configurable policy settings for category actions.

CREATE TABLE IF NOT EXISTS tenant_policy_settings (
  tenant_id INTEGER PRIMARY KEY,
  pii_action TEXT NOT NULL DEFAULT 'redact',
  financial_action TEXT NOT NULL DEFAULT 'redact',
  secrets_action TEXT NOT NULL DEFAULT 'block',
  health_action TEXT NOT NULL DEFAULT 'redact',
  ip_action TEXT NOT NULL DEFAULT 'redact',
  block_threshold TEXT NOT NULL DEFAULT 'critical',
  store_original_prompt INTEGER NOT NULL DEFAULT 1,
  show_sanitized_prompt_admin INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

INSERT INTO tenant_policy_settings (
  tenant_id,
  pii_action,
  financial_action,
  secrets_action,
  health_action,
  ip_action,
  block_threshold,
  store_original_prompt,
  show_sanitized_prompt_admin,
  created_at,
  updated_at
)
SELECT
  t.id,
  'redact',
  'redact',
  'block',
  'redact',
  'redact',
  'critical',
  1,
  1,
  datetime('now'),
  datetime('now')
FROM tenants t
LEFT JOIN tenant_policy_settings s ON s.tenant_id = t.id
WHERE s.tenant_id IS NULL;
