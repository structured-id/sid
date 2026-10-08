-- The completion of a caller's keyed command, committed in the transaction of
-- the command's own effect. A retry under the same key finds it instead of
-- executing the command again; the key is unique within the authorized
-- namespace (actor/scope) it was used in.
CREATE TABLE IF NOT EXISTS operation_results (
    namespace TEXT NOT NULL,
    op_key TEXT NOT NULL,
    method TEXT NOT NULL,
    -- Digest of the command's significant inputs: the same key with other
    -- inputs is a conflict, not a retry.
    fingerprint BYTEA NOT NULL,
    result BYTEA NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (namespace, op_key)
);
