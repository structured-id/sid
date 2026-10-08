-- Private password history: per-owner epochs,
-- each with its own sealed VOPRF key and KSF configuration, and the retained
-- KSF outputs of accepted passwords. History belongs to the owner, not to a
-- credential row: replacing or deleting a password leaves it in place.

-- One row per owner with history; its revision moves on every write, so a
-- commit made against a stale read writes nothing.
CREATE TABLE IF NOT EXISTS password_histories (
    owner_id    UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    revision    BIGINT NOT NULL CHECK (revision > 0)
);

-- One history key and its manifest. The key is written sealed, before its
-- first use, and never regenerated.
CREATE TABLE IF NOT EXISTS password_history_epochs (
    id              UUID PRIMARY KEY,
    owner_id        UUID NOT NULL REFERENCES password_histories(owner_id) ON DELETE CASCADE,
    suite           TEXT NOT NULL CHECK (suite IN ('pallas-poseidon-v1')),
    public_key      BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    wrapped_key     BYTEA NOT NULL,
    ksf_memory_kib  INTEGER NOT NULL CHECK (ksf_memory_kib > 0),
    ksf_passes      INTEGER NOT NULL CHECK (ksf_passes > 0),
    ksf_lanes       INTEGER NOT NULL CHECK (ksf_lanes > 0),
    ksf_salt        BYTEA NOT NULL CHECK (octet_length(ksf_salt) = 32),
    status          TEXT NOT NULL CHECK (status IN ('active', 'compare_only', 'retired')),
    created_at      TIMESTAMPTZ NOT NULL
);

-- New entries go under exactly one epoch per owner.
CREATE UNIQUE INDEX IF NOT EXISTS password_history_one_active_epoch
    ON password_history_epochs (owner_id) WHERE status = 'active';

-- The KSF output of an accepted password under one epoch, with the operation
-- and policy its proof was accepted under. Rejected candidates never get here.
CREATE TABLE IF NOT EXISTS password_history_entries (
    epoch_id        UUID NOT NULL REFERENCES password_history_epochs(id) ON DELETE CASCADE,
    owner_id        UUID NOT NULL REFERENCES password_histories(owner_id) ON DELETE CASCADE,
    seq             BIGINT NOT NULL,
    entry           BYTEA NOT NULL CHECK (octet_length(entry) = 32),
    operation_id    UUID NOT NULL,
    policy_version  INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (epoch_id, seq)
);

CREATE INDEX IF NOT EXISTS password_history_entries_owner
    ON password_history_entries (owner_id, seq);

-- History digests of the former Poseidon construction, kept out of the
-- credential rows and never written again. They keep the retention
-- constraints they already carry until a versioned legacy comparison domain
-- consumes them; they are not new-format protection.
CREATE TABLE IF NOT EXISTS password_history_legacy (
    credential_id   UUID PRIMARY KEY,
    owner_id        UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    digest          BYTEA NOT NULL,
    salt            BYTEA NOT NULL,
    proof_verified  BOOLEAN NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL
);

INSERT INTO password_history_legacy (credential_id, owner_id, digest, salt, proof_verified, created_at)
SELECT id, profile_id, history_commitment, commitment_salt, zkpp_verified, created_at
FROM credentials
WHERE history_commitment IS NOT NULL AND commitment_salt IS NOT NULL
ON CONFLICT (credential_id) DO NOTHING;

ALTER TABLE credentials DROP COLUMN IF EXISTS history_commitment;
ALTER TABLE credentials DROP COLUMN IF EXISTS commitment_salt;
