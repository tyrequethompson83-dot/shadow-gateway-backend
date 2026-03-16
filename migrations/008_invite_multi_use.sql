-- Add multi-use support for invite tokens while preserving single-use behavior.

ALTER TABLE invite_tokens ADD COLUMN IF NOT EXISTS max_uses INTEGER;
ALTER TABLE invite_tokens ADD COLUMN IF NOT EXISTS uses_count INTEGER NOT NULL DEFAULT 0;

-- Backfill legacy single-use invites that were already consumed.
UPDATE invite_tokens
SET uses_count = 1
WHERE used_at IS NOT NULL
  AND max_uses IS NULL
  AND COALESCE(uses_count, 0) = 0;
