-- Add missing columns to oauth2_clients that exist in the Rust model
-- but were never added to the database schema.
-- All columns are nullable or have defaults for backward compatibility.

-- Subject type: 'public' (default) or 'pairwise'.
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS subject_type VARCHAR(20) NOT NULL DEFAULT 'public';

-- Sector identifier URI for pairwise subject calculation.
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS sector_identifier_uri TEXT;

-- How the client authenticates at the token endpoint.
-- Values: 'none', 'client_secret_post', 'client_secret_basic', 'private_key_jwt'
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method VARCHAR(32) NOT NULL DEFAULT 'client_secret_post';

-- Response types (e.g. 'code'). Space-separated like other multi-value fields.
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS response_types TEXT NOT NULL DEFAULT 'code';

-- Contact emails. Comma-separated.
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS contacts TEXT NOT NULL DEFAULT '';

-- Dynamically registered flag.
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS dynamically_registered BOOLEAN NOT NULL DEFAULT FALSE;

-- Registration access token hash (RFC 7592).
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS registration_access_token_hash BYTEA;

-- Logo URI for consent screen.
-- (Already exists from migration 20260316_003, but ensure it's there)
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS logo_uri TEXT;

-- Organization binding for pairwise sub derivation (#762, #764).
-- Immutable UUIDv7 as string. NULL = no org (legacy CE clients).
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS org_id TEXT;

-- Client ID issued at timestamp.
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS client_id_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Client secret expiry.
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS client_secret_expires_at TIMESTAMPTZ;
