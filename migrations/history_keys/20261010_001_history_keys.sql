-- The password-history evaluator's own store: per-owner VOPRF keys and the
-- lifecycle that decides which replaced keys stay in use. Keyed by the owner's
-- history input domain (32 bytes); it holds no account, entry or credential
-- data and references no table outside this set, so it can live in its own
-- database under its own role.

-- One history key and its public manifest. The key is written sealed, before
-- its first use, and never regenerated; retiring an epoch keeps it.
CREATE TABLE IF NOT EXISTS history_key_epochs (
    id              UUID PRIMARY KEY,
    owner_domain    BYTEA NOT NULL CHECK (octet_length(owner_domain) = 32),
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
CREATE UNIQUE INDEX IF NOT EXISTS history_key_one_active_epoch
    ON history_key_epochs (owner_domain) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS history_key_epochs_owner
    ON history_key_epochs (owner_domain);

-- The newest live set the credential service reported per owner: one
-- revision, one set (sorted, without duplicates).
CREATE TABLE IF NOT EXISTS history_key_lifecycle (
    owner_domain BYTEA PRIMARY KEY CHECK (octet_length(owner_domain) = 32),
    revision     BIGINT NOT NULL CHECK (revision >= 0),
    live_epochs  UUID[] NOT NULL
);

-- The history revision at which an epoch stopped being active: a live set
-- older than it was read while the epoch could still take entries.
CREATE TABLE IF NOT EXISTS history_key_replaced (
    epoch_id             UUID PRIMARY KEY REFERENCES history_key_epochs(id) ON DELETE CASCADE,
    owner_domain         BYTEA NOT NULL CHECK (octet_length(owner_domain) = 32),
    replaced_at_revision BIGINT NOT NULL CHECK (replaced_at_revision > 0)
);

-- Epochs a prepared operation still uses: none of them is retired until the
-- operation is named settled or its expiry passes.
CREATE TABLE IF NOT EXISTS history_key_uses (
    operation_id UUID NOT NULL,
    epoch_id     UUID NOT NULL REFERENCES history_key_epochs(id) ON DELETE CASCADE,
    owner_domain BYTEA NOT NULL CHECK (octet_length(owner_domain) = 32),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (operation_id, epoch_id)
);

CREATE INDEX IF NOT EXISTS history_key_uses_owner
    ON history_key_uses (owner_domain, epoch_id);

-- The history write cutoff as this evaluator applies it: no epoch created
-- before `not_before` is selected to take entries or evaluated for one. One
-- row from the start, raised monotonically; NULL means no cutoff was set.
CREATE TABLE IF NOT EXISTS history_key_write_cutoff (
    singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    not_before TIMESTAMPTZ
);
INSERT INTO history_key_write_cutoff (singleton) VALUES (TRUE) ON CONFLICT DO NOTHING;

-- Every mutation of this store, written in its own transaction.
CREATE TABLE IF NOT EXISTS history_key_audit (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id    TEXT NOT NULL,
    actor_type  TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    metadata    JSONB NOT NULL
);
