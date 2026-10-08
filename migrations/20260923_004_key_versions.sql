-- Non-secret derivation parameters of the field-encryption key versions.
-- With the master secret (held outside the database) they reconstruct every
-- version; without them a version cannot be recovered, so they are kept for as
-- long as any field encrypted under the version may exist.
CREATE TABLE IF NOT EXISTS key_versions (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    salt BYTEA NOT NULL,
    algorithm TEXT NOT NULL,
    context TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
