-- Non-secret derivation parameters of the key versions sealing this store's
-- history keys. The evaluator holds its own key custody: with its master
-- secret (kept outside the database) these reconstruct every version, and a
-- sealed key whose version is missing here cannot be opened, so a version is
-- kept for as long as any key sealed under it may exist.
CREATE TABLE IF NOT EXISTS history_key_versions (
    version    INTEGER PRIMARY KEY CHECK (version > 0),
    salt       BYTEA NOT NULL,
    algorithm  TEXT NOT NULL,
    context    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
