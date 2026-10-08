-- Profile blobs: encrypted profile data for blind vault.
-- Blobs are opaque ciphertext — storage never decrypts.
-- Optimistic concurrency via version column.
CREATE TABLE IF NOT EXISTS profile_blobs (
    profile_id UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    storage_status TEXT NOT NULL DEFAULT 'local',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
