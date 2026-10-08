-- Refresh token family tracking for rotation chain and theft detection.
-- family_id groups all tokens in a rotation chain.
-- grace_expires_at allows old tokens to be used briefly after rotation (concurrent retries).

-- Add family_id column (default = id for self-referential first token in chain)
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family_id UUID;
UPDATE refresh_tokens SET family_id = id WHERE family_id IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;

-- Add grace window expiration
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS grace_expires_at TIMESTAMPTZ;

-- Index for family-level operations (theft detection: revoke all tokens in family)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
