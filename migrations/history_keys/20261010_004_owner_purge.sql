-- Owners whose profile was deleted and whose keys this store destroyed. The
-- row fences the domain: a preparation of the owner still in flight creates,
-- imports or selects no epoch. It is kept while such a preparation could be
-- within its operation's expiry, then compacted.
CREATE TABLE IF NOT EXISTS history_key_purged (
    owner_domain BYTEA PRIMARY KEY CHECK (octet_length(owner_domain) = 32),
    purged_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
