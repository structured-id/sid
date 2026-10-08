-- Site Login Policy: per-client login strategy
-- See: arch/auth/unified-login-flow.md §Site Login Policy

ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS login_strategy TEXT NOT NULL DEFAULT 'local_first',
    ADD COLUMN IF NOT EXISTS show_federation_button BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS federation_timeout_ms INTEGER NOT NULL DEFAULT 500,
    ADD COLUMN IF NOT EXISTS unified_input BOOLEAN NOT NULL DEFAULT FALSE;
