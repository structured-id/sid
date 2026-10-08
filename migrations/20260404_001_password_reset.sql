-- Password reset sessions + recovery backups.

CREATE TABLE IF NOT EXISTS password_reset_sessions (
    id              UUID PRIMARY KEY,
    profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    token_hash      VARCHAR(255) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    shard_downloaded BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    verified_at     TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

-- Fast lookup by profile (rate limiting: max 3 per email per 5 min)
CREATE INDEX IF NOT EXISTS idx_password_reset_sessions_profile
    ON password_reset_sessions(profile_id, created_at DESC);

-- Cleanup index for expired sessions
CREATE INDEX IF NOT EXISTS idx_password_reset_sessions_expired
    ON password_reset_sessions(expires_at)
    WHERE status = 'pending';

-- Recovery backups: encrypted data_key + BIP-39 seed hash.
-- One backup per profile (UPSERT).
CREATE TABLE IF NOT EXISTS recovery_backups (
    profile_id          UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    encrypted_data_key  BYTEA NOT NULL,
    seed_hash           BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
