-- Add token tracking to daily tenant usage for optional token-based quota control.

ALTER TABLE tenant_usage_daily
ADD COLUMN IF NOT EXISTS token_count INTEGER NOT NULL DEFAULT 0;
