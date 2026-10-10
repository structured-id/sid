-- Reclaiming the keys of first enrollments that never committed.

-- The operation whose first enrollment created an epoch, recorded with the
-- key in the same transaction. NULL for an epoch made otherwise (a rotation,
-- a key created for an existing owner, an imported archive): those are never
-- reclaimed as an abandoned enrollment.
ALTER TABLE history_key_epochs ADD COLUMN IF NOT EXISTS created_by UUID;

CREATE INDEX IF NOT EXISTS history_key_epochs_created_by
    ON history_key_epochs (created_by) WHERE created_by IS NOT NULL;

-- First enrollments the credential authority aborted: such an operation
-- creates no key and is evaluated no more, even when its preparation
-- arrives after the cleanup.
CREATE TABLE IF NOT EXISTS history_key_abandoned (
    operation_id UUID PRIMARY KEY,
    owner_domain BYTEA NOT NULL CHECK (octet_length(owner_domain) = 32),
    abandoned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
