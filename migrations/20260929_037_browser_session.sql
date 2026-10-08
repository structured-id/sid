-- IdP browser session (SSO at authorize): a session a browser signed in with
-- carries the hash of the random secret in its `__Host-sid_session` cookie;
-- the secret itself is never stored.
ALTER TABLE sessions ADD COLUMN browser_secret_hash BYTEA;
CREATE UNIQUE INDEX sessions_browser_secret_hash
    ON sessions (browser_secret_hash) WHERE browser_secret_hash IS NOT NULL;

-- A session redeemed from a grant names the IdP session whose authentication
-- it reuses: ending that session ends the sessions it authenticated.
ALTER TABLE sessions
    ADD COLUMN authenticated_by UUID REFERENCES sessions(id) ON DELETE SET NULL;
CREATE INDEX sessions_authenticated_by
    ON sessions (authenticated_by) WHERE authenticated_by IS NOT NULL;

-- An authorization code carries the authentication of the session that
-- authorized it: the tokens it redeems into report when and how the user
-- actually authenticated (`auth_time`, `amr`, `acr`), not the exchange.
-- Codes live minutes and those issued before carry none of it; they end here.
DELETE FROM authorization_codes;
ALTER TABLE authorization_codes
    ADD COLUMN authorizing_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ADD COLUMN authenticated_at TIMESTAMPTZ NOT NULL,
    ADD COLUMN amr TEXT NOT NULL,
    ADD COLUMN assurance_level TEXT NOT NULL,
    ADD COLUMN elevation_level TEXT,
    ADD COLUMN elevation_until TIMESTAMPTZ;
