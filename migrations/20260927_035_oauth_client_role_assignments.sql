-- An independent OAuth client holds roles as its own principal (for example
-- the token inspector role on one protected resource). Its assignments go
-- with the client.
ALTER TABLE role_assignments
    ADD COLUMN IF NOT EXISTS oauth_client_id TEXT
    REFERENCES oauth2_clients(client_id) ON DELETE CASCADE;

ALTER TABLE role_assignments DROP CONSTRAINT IF EXISTS chk_principal;
ALTER TABLE role_assignments ADD CONSTRAINT chk_principal CHECK (
    num_nonnulls(profile_id, group_id, machine_user_id, oauth_client_id) = 1
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_oauth_client_id
    ON role_assignments(oauth_client_id);
