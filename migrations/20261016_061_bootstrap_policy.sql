-- The installation's bootstrap policy (auth/enrollment-policy.md, First
-- Administrator). A row exists only once the installation is centrally
-- managed, and is never removed: no restart, restore of later data or
-- configuration reopens its local administrator claim. Without a row the
-- installation is self-managed.
CREATE TABLE IF NOT EXISTS bootstrap_policy (
    scope TEXT PRIMARY KEY CHECK (scope = 'installation'),
    policy TEXT NOT NULL CHECK (policy = 'centrally_managed'),
    adopted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
