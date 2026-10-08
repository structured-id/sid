-- Recovery shards for Shamir key recovery.
-- Each profile has up to 3 shards (device, cloud, SID server).
-- Only SID shard (shard_type='sid') has encrypted_data on server.
-- Device and cloud shards are metadata-only records.

CREATE TABLE IF NOT EXISTS recovery_shards (
    id              UUID PRIMARY KEY,
    profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    shard_type      VARCHAR(20) NOT NULL,  -- 'device', 'cloud', 'sid', 'trusted_person'
    shamir_preset   VARCHAR(30) NOT NULL DEFAULT 'owner_cloud_sid',
    shard_index     SMALLINT NOT NULL,     -- Shamir x-coordinate (1-255)
    encrypted_data  BYTEA,                 -- Only for shard_type='sid'
    server_pepper   BYTEA NOT NULL,        -- 32 bytes, per-profile, for identity-derived key
    cloud_hint      VARCHAR(255),          -- e.g. 'icloud:/SID/recovery-shard.enc'
    trusted_person_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    consumed        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One shard per type per profile (UPSERT target)
CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_shards_profile_type
    ON recovery_shards(profile_id, shard_type);

-- Fast lookup for SID shard download during password reset
CREATE INDEX IF NOT EXISTS idx_recovery_shards_sid_unconsumed
    ON recovery_shards(profile_id)
    WHERE shard_type = 'sid' AND consumed = FALSE;
