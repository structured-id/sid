-- Initial access tokens for dynamic client registration (RFC 7591 §3).
-- The token itself is never stored, only its SHA-256 hash.
CREATE TABLE IF NOT EXISTS initial_access_tokens (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    max_clients INTEGER NOT NULL CHECK (max_clients >= 0),
    clients_registered INTEGER NOT NULL DEFAULT 0 CHECK (clients_registered >= 0),
    allowed_scopes TEXT NOT NULL DEFAULT '',
    allowed_grant_types TEXT NOT NULL DEFAULT '',
    allowed_redirect_patterns TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_initial_access_tokens_project
    ON initial_access_tokens (project_id);

-- The token a client was dynamically registered with; its constraints bound
-- the client's self-service updates (RFC 7592 §2.2). NULL = created by an
-- administrator. It replaces the bare flag: no token table existed, so no
-- client can have been registered dynamically before this migration.
ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS registration_iat UUID;
ALTER TABLE oauth2_clients DROP COLUMN IF EXISTS dynamically_registered;
