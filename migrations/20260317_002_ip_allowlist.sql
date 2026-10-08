-- Admin-configured IP allowlist entries.
-- Allowlisted IPs/CIDRs override ALL negative IP intelligence labels.

CREATE TABLE IF NOT EXISTS ip_allowlist_entries (
    cidr        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
