-- The evaluator's record of each owner's history lifecycle. The credential
-- service, which holds the entries, sends the live set (epochs holding an
-- entry) with its revision when it prepares an operation; the evaluator keeps
-- the newest one, never reads an entry, and retires a replaced epoch only from
-- it. Retiring an epoch keeps its sealed key.

-- The newest live set accepted per owner: one revision, one set.
CREATE TABLE IF NOT EXISTS password_history_lifecycle (
    owner_id    UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    revision    BIGINT NOT NULL CHECK (revision >= 0),
    -- Sorted, without duplicates.
    live_epochs UUID[] NOT NULL
);

-- The history revision at which an epoch stopped being active: a live set
-- older than it was read while the epoch could still take entries.
CREATE TABLE IF NOT EXISTS password_history_replaced (
    epoch_id             UUID PRIMARY KEY REFERENCES password_history_epochs(id) ON DELETE CASCADE,
    owner_id             UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    replaced_at_revision BIGINT NOT NULL CHECK (replaced_at_revision > 0)
);

-- Epochs a prepared operation still uses: none of them is retired until the
-- operation is named settled or its expiry passes.
CREATE TABLE IF NOT EXISTS password_history_uses (
    operation_id UUID NOT NULL,
    epoch_id     UUID NOT NULL REFERENCES password_history_epochs(id) ON DELETE CASCADE,
    owner_id     UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (operation_id, epoch_id)
);

CREATE INDEX IF NOT EXISTS password_history_uses_owner
    ON password_history_uses (owner_id, epoch_id);

-- Compare-only epochs that exist before this record were replaced no later
-- than their owner's current revision.
INSERT INTO password_history_replaced (epoch_id, owner_id, replaced_at_revision)
SELECT e.id, e.owner_id, h.revision
FROM password_history_epochs e
JOIN password_histories h ON h.owner_id = e.owner_id
WHERE e.status = 'compare_only'
ON CONFLICT (epoch_id) DO NOTHING;
