-- Add deferred ZK proof verification deadline to credentials.
-- Used for no-WASM fallback: OPAQUE registration without ZK proof gets 24h to submit.
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS zk_verification_deadline TIMESTAMPTZ;
