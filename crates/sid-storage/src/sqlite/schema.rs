// SPDX-License-Identifier: AGPL-3.0-only
//! The SQLite baseline schema: version 1 of a database file.
//!
//! Frozen: a file created from it is upgraded by the versioned migrations in
//! [`super::migrations`], so a change to the schema is a new migration, never
//! an edit here. Foreign keys and WAL are connection options, not part of it.

/// Every table, index and constraint of schema version 1.
pub(crate) const BASELINE: &str = r#"
-- StructuredID CE — SQLite schema version 1

--------------------------------------------------------------------------------
-- profiles
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profiles (
    id              TEXT PRIMARY KEY,
    username        TEXT UNIQUE,
    given_name          TEXT,
    family_name         TEXT,
    middle_name         TEXT,
    honorific_prefix    TEXT,
    honorific_suffix    TEXT,
    profile_type    TEXT NOT NULL DEFAULT 'personal',
    status          TEXT NOT NULL DEFAULT 'active',
    visibility      TEXT NOT NULL DEFAULT 'public',
    roles           TEXT NOT NULL DEFAULT '',
    max_assurance   TEXT NOT NULL DEFAULT 'anonymous',
    manager_id      TEXT REFERENCES profiles(id) ON DELETE SET NULL,
    migration_pending       INTEGER NOT NULL DEFAULT 0,
    migration_started_at    TEXT,
    migration_completed_at  TEXT,
    revision        INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_profiles_username ON profiles(username);
CREATE INDEX IF NOT EXISTS idx_profiles_status ON profiles(status);
DROP INDEX IF EXISTS idx_profiles_created_at;
CREATE INDEX IF NOT EXISTS idx_profiles_created_id ON profiles(created_at, id);
CREATE INDEX IF NOT EXISTS idx_profiles_migration_pending ON profiles(migration_pending) WHERE migration_pending = 1;

-- Auto-update updated_at trigger
CREATE TRIGGER IF NOT EXISTS update_profiles_updated_at
    AFTER UPDATE ON profiles
    FOR EACH ROW
    BEGIN
        UPDATE profiles SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
    END;

--------------------------------------------------------------------------------
-- profile_phones
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profile_phones (
    id                  TEXT PRIMARY KEY,
    profile_id          TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    e164                INTEGER NOT NULL,
    extension           INTEGER,
    label               TEXT NOT NULL DEFAULT 'mobile',
    custom_label        TEXT,
    is_primary          INTEGER NOT NULL DEFAULT 0,
    can_receive_sms     INTEGER NOT NULL DEFAULT 1,
    can_receive_fax     INTEGER NOT NULL DEFAULT 0,
    can_receive_voice   INTEGER NOT NULL DEFAULT 1,
    verified            INTEGER NOT NULL DEFAULT 0,
    verified_at         TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_phones_profile_e164
    ON profile_phones (profile_id, e164);
CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_phones_primary
    ON profile_phones (profile_id) WHERE is_primary = 1;
CREATE INDEX IF NOT EXISTS idx_profile_phones_profile_id
    ON profile_phones (profile_id);

CREATE TRIGGER IF NOT EXISTS update_profile_phones_updated_at
    AFTER UPDATE ON profile_phones
    FOR EACH ROW
    BEGIN
        UPDATE profile_phones SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
    END;

--------------------------------------------------------------------------------
-- profile_emails
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profile_emails (
    id              TEXT PRIMARY KEY,
    profile_id      TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT 'personal',
    custom_label    TEXT,
    is_primary      INTEGER NOT NULL DEFAULT 0,
    verified        INTEGER NOT NULL DEFAULT 0,
    verified_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_emails_profile_email
    ON profile_emails (profile_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_emails_primary
    ON profile_emails (profile_id) WHERE is_primary = 1;
CREATE INDEX IF NOT EXISTS idx_profile_emails_profile_id
    ON profile_emails (profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_emails_email
    ON profile_emails (email);

CREATE TRIGGER IF NOT EXISTS update_profile_emails_updated_at
    AFTER UPDATE ON profile_emails
    FOR EACH ROW
    BEGIN
        UPDATE profile_emails SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
    END;

--------------------------------------------------------------------------------
-- credentials
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS credentials (
    id                  TEXT PRIMARY KEY,
    profile_id          TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    credential_type     TEXT NOT NULL
        CHECK (credential_type IN ('opaque', 'webauthn', 'totp', 'recovery', 'legacy_hash')),
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    data                BLOB NOT NULL,
    label               TEXT,
    policy_version      INTEGER,
    zkpp_verified       INTEGER NOT NULL DEFAULT 0,
    opaque_curve        INTEGER,
    legacy_algorithm    TEXT,
    -- RFC 9807 credential_identifier of a password: its own OPRF key.
    opaque_credential_identifier BLOB CHECK (length(opaque_credential_identifier) = 16),
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_credentials_profile_id ON credentials(profile_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_credentials_profile_type ON credentials(profile_id, credential_type);
-- A profile has one password: at most one active OPAQUE credential.
CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_active_opaque
    ON credentials(profile_id) WHERE credential_type = 'opaque' AND status = 'active';

--------------------------------------------------------------------------------
-- password history (arch/auth/password-history.md): per-owner epochs with
-- sealed VOPRF keys, and the KSF outputs of accepted passwords. History
-- belongs to the owner and outlives any credential row.
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS password_histories (
    owner_id    TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    revision    INTEGER NOT NULL CHECK (revision > 0)
);

CREATE TABLE IF NOT EXISTS password_history_epochs (
    id              TEXT PRIMARY KEY,
    owner_id        TEXT NOT NULL REFERENCES password_histories(owner_id) ON DELETE CASCADE,
    suite           TEXT NOT NULL CHECK (suite IN ('pallas-poseidon-v1')),
    public_key      BLOB NOT NULL CHECK (length(public_key) = 32),
    wrapped_key     BLOB NOT NULL,
    ksf_memory_kib  INTEGER NOT NULL CHECK (ksf_memory_kib > 0),
    ksf_passes      INTEGER NOT NULL CHECK (ksf_passes > 0),
    ksf_lanes       INTEGER NOT NULL CHECK (ksf_lanes > 0),
    ksf_salt        BLOB NOT NULL CHECK (length(ksf_salt) = 32),
    status          TEXT NOT NULL CHECK (status IN ('active', 'compare_only', 'retired')),
    created_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS password_history_one_active_epoch
    ON password_history_epochs (owner_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS password_history_entries (
    epoch_id        TEXT NOT NULL REFERENCES password_history_epochs(id) ON DELETE CASCADE,
    owner_id        TEXT NOT NULL REFERENCES password_histories(owner_id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    entry           BLOB NOT NULL CHECK (length(entry) = 32),
    operation_id    TEXT NOT NULL,
    policy_version  INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (epoch_id, seq)
);

CREATE INDEX IF NOT EXISTS password_history_entries_owner
    ON password_history_entries (owner_id, seq);

--------------------------------------------------------------------------------
-- sessions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sessions (
    id                TEXT PRIMARY KEY,
    profile_id        TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    client_id         TEXT,
    device_id         TEXT,
    ip_address        TEXT NOT NULL,
    user_agent        TEXT,
    scopes            TEXT NOT NULL DEFAULT '',
    assurance_level   TEXT NOT NULL CHECK (assurance_level IN ('basic', 'standard')),
    elevation_level   TEXT,
    elevation_until   TEXT,
    is_provisional    INTEGER NOT NULL DEFAULT 0,
    passkey_prompt    INTEGER NOT NULL DEFAULT 0,
    authenticated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    amr               TEXT NOT NULL DEFAULT '',
    policy_grace      INTEGER NOT NULL DEFAULT 0,
    grace_deadline    TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at        TEXT NOT NULL,
    last_activity_at  TEXT,
    -- Hash of the secret in a browser's IdP session cookie; the secret is
    -- never stored.
    browser_secret_hash BLOB UNIQUE,
    -- The IdP session whose authentication a session redeemed from a grant
    -- reuses; ending it ends this one.
    authenticated_by  TEXT REFERENCES sessions(id) ON DELETE SET NULL,
    CHECK ((elevation_level IS NULL AND elevation_until IS NULL)
        OR (elevation_level IN ('elevated', 'critical') AND elevation_until IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_sessions_profile_id ON sessions(profile_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_client_id ON sessions(client_id) WHERE client_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_authenticated_by ON sessions(authenticated_by) WHERE authenticated_by IS NOT NULL;

--------------------------------------------------------------------------------
-- principals
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS principals (
    id              TEXT PRIMARY KEY,
    principal_type  TEXT NOT NULL,
    value           TEXT NOT NULL,
    verified        INTEGER NOT NULL DEFAULT 0,
    verified_at     TEXT,
    verification_expires TEXT,
    assigned_profile_id TEXT,
    assignment_revision INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_principals_type_value ON principals(principal_type, value);
CREATE INDEX IF NOT EXISTS idx_principals_value ON principals(value);
CREATE INDEX IF NOT EXISTS idx_principals_assigned ON principals(assigned_profile_id);

CREATE TABLE IF NOT EXISTS principal_bindings (
    id              TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    profile_id      TEXT NOT NULL,
    is_primary      INTEGER NOT NULL DEFAULT 0,
    source_field    TEXT,
    source_email_id TEXT REFERENCES profile_emails(id) ON DELETE SET NULL,
    source_phone_id TEXT REFERENCES profile_phones(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (principal_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_principal_bindings_principal_id ON principal_bindings(principal_id);
CREATE INDEX IF NOT EXISTS idx_principal_bindings_profile ON principal_bindings(profile_id);

--------------------------------------------------------------------------------
-- projects
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner_id    TEXT REFERENCES profiles(id) ON DELETE SET NULL,
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id) WHERE owner_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS update_projects_updated_at
    AFTER UPDATE ON projects
    FOR EACH ROW
    BEGIN
        UPDATE projects SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
    END;

-- Default system project
INSERT OR IGNORE INTO projects (id, name, description, is_system)
VALUES ('00000000-0000-0000-0000-000000000000', 'SID', 'Default system project', 1);

--------------------------------------------------------------------------------
-- applications: the container of a client role, a resource role, or both
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS applications (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id),
    name        TEXT NOT NULL,
    -- The installation's own integration this is; each exists at most once.
    system_integration TEXT UNIQUE,
    revision    INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    -- Target of the composite key below: a role's project is its application's.
    UNIQUE (id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id);

--------------------------------------------------------------------------------
-- oauth2_clients
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oauth2_clients (
    client_id                           TEXT PRIMARY KEY,
    -- One client role per application, in the application's project.
    application_id                      TEXT NOT NULL UNIQUE,
    -- The resource a token is for when a request names none.
    default_resource                    TEXT REFERENCES protected_resources(id),
    client_secret_hash                  BLOB,
    -- Public keys of a private_key_jwt client: a JWK Set as JSON text.
    jwks                                TEXT,
    -- Redirect URIs: a JSON array of strings (a URI may hold a comma).
    redirect_uris                       TEXT NOT NULL DEFAULT '[]',
    allowed_scopes                      TEXT NOT NULL DEFAULT 'openid profile email',
    grant_types                         TEXT NOT NULL DEFAULT 'authorization_code',
    client_name                         TEXT NOT NULL,
    active                              INTEGER NOT NULL DEFAULT 1,
    project_id                          TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'
                                        REFERENCES projects(id),
    application_type                    TEXT NOT NULL DEFAULT 'web',
    required_acr                        TEXT,
    required_amr                        TEXT NOT NULL DEFAULT '',
    enforcement_mode                    TEXT NOT NULL DEFAULT 'audit',
    min_device_assurance                TEXT,
    require_verified_email              INTEGER,
    require_verified_phone              INTEGER,
    backchannel_logout_uri              TEXT,
    backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0,
    -- Post-logout redirect URIs: a JSON array of strings.
    post_logout_redirect_uris           TEXT NOT NULL DEFAULT '[]',
    claim_mappings                      TEXT,
    logo_uri                            TEXT,
    token_endpoint_auth_method          TEXT NOT NULL DEFAULT 'client_secret_basic',
    response_types                      TEXT NOT NULL DEFAULT 'code',
    subject_type                        TEXT NOT NULL DEFAULT 'public',
    sector_identifier_uri               TEXT,
    -- Contact addresses: a JSON array of strings.
    contacts                            TEXT NOT NULL DEFAULT '[]',
    client_id_issued_at                 TEXT NOT NULL,
    client_secret_expires_at            TEXT,
    -- The initial access token a dynamically registered client came from.
    registration_iat                    TEXT,
    registration_access_token_hash      BLOB,
    login_strategy                      TEXT NOT NULL DEFAULT 'local_first',
    show_federation_button              INTEGER NOT NULL DEFAULT 1,
    federation_timeout_ms               INTEGER NOT NULL DEFAULT 500,
    unified_input                       INTEGER NOT NULL DEFAULT 0,
    org_id                             TEXT REFERENCES organizations(id),
    revision                            INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at                          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (application_id, project_id) REFERENCES applications (id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_project ON oauth2_clients(project_id);

-- Protected-resource roles. A row is never deleted: removing its application
-- retires it (application_id NULL), so its indicator is never given to
-- another resource of the issuer.
CREATE TABLE IF NOT EXISTS protected_resources (
    id              TEXT PRIMARY KEY,
    application_id  TEXT UNIQUE REFERENCES applications(id),
    issuer_id       TEXT NOT NULL REFERENCES oidc_issuers(id),
    indicator       TEXT NOT NULL,
    scopes          TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL CHECK (state IN ('active', 'inactive', 'retired')),
    revision        INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (issuer_id, indicator),
    CHECK ((state = 'retired') = (application_id IS NULL))
);

-- Explicit permission of one client to obtain tokens for one resource. The
-- client is an OAuth client or a machine user; `client_id` is its identifier
-- either way. SQLite keys a generated column by a unique index, not a
-- primary key.
CREATE TABLE IF NOT EXISTS resource_access (
    oauth_client_id    TEXT REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    machine_client_id  TEXT REFERENCES machine_users(client_id) ON DELETE CASCADE,
    client_id          TEXT NOT NULL
                       GENERATED ALWAYS AS (COALESCE(oauth_client_id, machine_client_id)) STORED,
    resource_id        TEXT NOT NULL REFERENCES protected_resources(id),
    scopes             TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    CHECK ((oauth_client_id IS NULL) != (machine_client_id IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_resource_access_client
    ON resource_access(client_id, resource_id);

CREATE INDEX IF NOT EXISTS idx_resource_access_resource ON resource_access(resource_id);

--------------------------------------------------------------------------------
-- refresh_tokens
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  BLOB NOT NULL UNIQUE,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '',
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked     INTEGER NOT NULL DEFAULT 0,
    replaced_by TEXT,
    family_id   TEXT NOT NULL,
    grace_expires_at TEXT,
    -- JWK thumbprint of the DPoP key the token is bound to.
    dpop_jkt    TEXT,
    -- The resource the grant was issued for (RFC 8707).
    resource_id TEXT NOT NULL REFERENCES protected_resources(id)
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_profile ON refresh_tokens(profile_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);

--------------------------------------------------------------------------------
-- authorization_codes
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash       BLOB PRIMARY KEY,
    profile_id      TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    scopes          TEXT NOT NULL DEFAULT '',
    code_challenge  TEXT,
    -- OIDC nonce of the authorization request, returned in the ID Token.
    nonce           TEXT,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    used            INTEGER NOT NULL DEFAULT 0,
    -- Session created by the redemption; a reuse of the code revokes it.
    session_id      TEXT,
    -- The resource the authorization was granted for (RFC 8707).
    resource_id     TEXT NOT NULL REFERENCES protected_resources(id),
    -- The authentication of the session that authorized the code, which the
    -- tokens it redeems into report.
    authorizing_session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    authenticated_at TEXT NOT NULL,
    amr             TEXT NOT NULL,
    assurance_level TEXT NOT NULL CHECK (assurance_level IN ('basic', 'standard')),
    elevation_level TEXT,
    elevation_until TEXT,
    CHECK ((elevation_level IS NULL AND elevation_until IS NULL)
        OR (elevation_level IN ('elevated', 'critical') AND elevation_until IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);

--------------------------------------------------------------------------------
-- initial_access_tokens
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS initial_access_tokens (
    id                        TEXT PRIMARY KEY,
    project_id                TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash                BLOB NOT NULL UNIQUE,
    max_clients               INTEGER NOT NULL DEFAULT 0,
    clients_registered        INTEGER NOT NULL DEFAULT 0,
    allowed_scopes            TEXT NOT NULL DEFAULT '',
    allowed_grant_types       TEXT NOT NULL DEFAULT '',
    allowed_redirect_patterns TEXT NOT NULL DEFAULT '',
    created_by                TEXT NOT NULL DEFAULT '',
    revoked                   INTEGER NOT NULL DEFAULT 0,
    expires_at                TEXT NOT NULL,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_iat_project ON initial_access_tokens(project_id);

--------------------------------------------------------------------------------
-- key_versions (non-secret derivation parameters of field-encryption keys)
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS key_versions (
    version     INTEGER PRIMARY KEY CHECK (version > 0),
    salt        BLOB NOT NULL,
    algorithm   TEXT NOT NULL,
    context     TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

--------------------------------------------------------------------------------
-- durable_work (required work committed with its state change; fenced claims)
--------------------------------------------------------------------------------

-- The completion of a caller's keyed command, committed with its effect.
CREATE TABLE IF NOT EXISTS operation_results (
    namespace    TEXT NOT NULL,
    op_key       TEXT NOT NULL,
    method       TEXT NOT NULL,
    fingerprint  BLOB NOT NULL,
    result       BLOB NOT NULL,
    completed_at TEXT NOT NULL,
    PRIMARY KEY (namespace, op_key)
);

-- One row per background job currently held: whoever inserted the row runs
-- the job until it deletes the row or the lease runs out.
CREATE TABLE IF NOT EXISTS job_locks (
    job        INTEGER PRIMARY KEY,
    holder     TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS durable_work (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    payload      BLOB NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending',
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    generation   INTEGER NOT NULL DEFAULT 0,
    lease_owner  TEXT,
    lease_until  TEXT,
    last_error   TEXT,
    ambiguous    INTEGER NOT NULL DEFAULT 0,
    result       TEXT,
    not_before   TEXT NOT NULL,
    expires_at   TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_durable_work_open
    ON durable_work (kind, not_before) WHERE state IN ('pending', 'claimed');

--------------------------------------------------------------------------------
-- instance_secrets (sealed secrets every replica shares; written once)
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS instance_secrets (
    name        TEXT PRIMARY KEY,
    sealed      BLOB NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

--------------------------------------------------------------------------------
-- organizations (the installation's own organization is `is_instance`)
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS organizations (
    id                TEXT PRIMARY KEY,
    org_type          TEXT NOT NULL
        CHECK (org_type IN ('family', 'community', 'commercial', 'government')),
    status            TEXT NOT NULL
        CHECK (status IN ('pending_dns', 'pending_claim', 'active_trial', 'active',
                          'suspended', 'deprovisioning', 'deleted')),
    canonical_domain  TEXT NOT NULL,
    is_instance       INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS organizations_one_instance
    ON organizations (is_instance) WHERE is_instance;

--------------------------------------------------------------------------------
-- oidc issuers: one per issuing authority and recipient organization; a handle
-- and a canonical URL belong to one issuer forever (rows are never deleted)
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oidc_issuers (
    id                TEXT PRIMARY KEY,
    handle            TEXT NOT NULL UNIQUE,
    canonical_url     TEXT NOT NULL UNIQUE,
    authority         TEXT NOT NULL CHECK (authority IN ('local')),
    recipient_org     TEXT NOT NULL REFERENCES organizations(id),
    created_at        TEXT NOT NULL,
    UNIQUE (authority, recipient_org)
);

-- Token-signing keys, one row per generation; the private key only sealed.
CREATE TABLE IF NOT EXISTS oidc_issuer_signing_keys (
    issuer_id           TEXT NOT NULL REFERENCES oidc_issuers(id),
    generation          INTEGER NOT NULL CHECK (generation >= 1),
    key_id              TEXT NOT NULL,
    public_key          BLOB NOT NULL CHECK (length(public_key) = 32),
    sealed_private_key  BLOB NOT NULL,
    created_at          TEXT NOT NULL,
    PRIMARY KEY (issuer_id, generation)
);

-- A Profile's pairwise identity at one organization (scope): the pairwise
-- `sub` of every client of that scope, allocated on the first visit.
CREATE TABLE IF NOT EXISTS service_bindings (
    binding_id    TEXT PRIMARY KEY,
    profile_id    TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    scope         TEXT NOT NULL CHECK (trim(scope) <> ''),
    binding_index INTEGER NOT NULL CHECK (binding_index >= 0),
    created_at    TEXT NOT NULL,
    last_used_at  TEXT NOT NULL,
    UNIQUE (profile_id, scope),
    UNIQUE (profile_id, binding_index)
);

--------------------------------------------------------------------------------
-- roles
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    key         TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    description TEXT,
    group_label TEXT,
    permissions TEXT NOT NULL DEFAULT '',
    revision    INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(project_id, name),
    UNIQUE(project_id, key)
);

CREATE INDEX IF NOT EXISTS idx_roles_project_id ON roles(project_id);

--------------------------------------------------------------------------------
-- groups
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS groups (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    parent_group_id TEXT REFERENCES groups(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_groups_project_id ON groups(project_id);
CREATE INDEX IF NOT EXISTS idx_groups_parent ON groups(parent_group_id) WHERE parent_group_id IS NOT NULL;

--------------------------------------------------------------------------------
-- group_members
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS group_members (
    group_id    TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (group_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_profile_id ON group_members(profile_id);

--------------------------------------------------------------------------------
-- role_assignments
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS role_assignments (
    id               TEXT PRIMARY KEY,
    profile_id       TEXT REFERENCES profiles(id) ON DELETE CASCADE,
    group_id         TEXT REFERENCES groups(id) ON DELETE CASCADE,
    machine_user_id  TEXT,
    -- An independent OAuth client as its own principal.
    oauth_client_id  TEXT REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    -- A provisioning connector as its own principal.
    provisioning_connector_id TEXT REFERENCES provisioning_connectors(id) ON DELETE CASCADE,
    role_id          TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope            TEXT,
    expires_at       TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- Who created it on what authority (D050 B); absent provenance confers no
    -- delegation authority. A redelegated administrative assignment ends with
    -- its source.
    granted_by               TEXT,
    basis_assignment_id      TEXT,
    depends_on_assignment_id TEXT REFERENCES role_assignments(id) ON DELETE CASCADE,
    revision                 INTEGER NOT NULL DEFAULT 0,
    CHECK (
        (profile_id IS NOT NULL) + (group_id IS NOT NULL) + (machine_user_id IS NOT NULL)
            + (oauth_client_id IS NOT NULL) + (provisioning_connector_id IS NOT NULL) = 1
    ),
    CHECK (granted_by IS NOT NULL
           OR (basis_assignment_id IS NULL AND depends_on_assignment_id IS NULL))
);

-- The envelope of an administrative assignment. A group recipients are
-- restricted to cannot be deleted from under it: that would widen it.
CREATE TABLE IF NOT EXISTS role_assignment_admin (
    assignment_id      TEXT PRIMARY KEY REFERENCES role_assignments(id) ON DELETE CASCADE,
    recipient_group_id TEXT REFERENCES groups(id) ON DELETE RESTRICT,
    max_validity_secs  INTEGER NOT NULL CHECK (max_validity_secs > 0)
);

CREATE TABLE IF NOT EXISTS role_assignment_admin_entries (
    assignment_id TEXT NOT NULL REFERENCES role_assignment_admin(assignment_id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('operation', 'recipient_kind', 'permission')),
    value         TEXT NOT NULL,
    PRIMARY KEY (assignment_id, kind, value),
    CHECK (kind <> 'operation' OR value IN ('assign', 'revoke', 'edit_role', 'redelegate')),
    CHECK (kind <> 'recipient_kind'
           OR value IN ('profile', 'group', 'machine_user', 'oauth_client'))
);

-- A deleted role leaves the envelope: that only narrows it.
CREATE TABLE IF NOT EXISTS role_assignment_admin_roles (
    assignment_id TEXT NOT NULL REFERENCES role_assignment_admin(assignment_id) ON DELETE CASCADE,
    role_id       TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (assignment_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_role_assignment_admin_roles_role
    ON role_assignment_admin_roles(role_id);

-- The permission ceiling an envelope approved a working assignment under; its
-- role is never edited past it while the assignment exists.
CREATE TABLE IF NOT EXISTS role_assignment_ceilings (
    assignment_id TEXT NOT NULL REFERENCES role_assignments(id) ON DELETE CASCADE,
    permission    TEXT NOT NULL,
    PRIMARY KEY (assignment_id, permission)
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_oauth_client_id ON role_assignments(oauth_client_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_provisioning_connector_id
    ON role_assignments(provisioning_connector_id);

CREATE INDEX IF NOT EXISTS idx_role_assignments_profile_id ON role_assignments(profile_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_group_id ON role_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_machine_user_id ON role_assignments(machine_user_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_role_id ON role_assignments(role_id);

--------------------------------------------------------------------------------
-- sod_conflict_rules
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sod_conflict_rules (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    description       TEXT,
    conflicting_roles TEXT NOT NULL DEFAULT '',
    severity          TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('warning', 'block'))
);

--------------------------------------------------------------------------------
-- cedar_policies
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cedar_policies (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    policy_text TEXT NOT NULL,
    effect      TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    revision    INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_cedar_policies_project_id ON cedar_policies(project_id);

--------------------------------------------------------------------------------
-- entity_attributes
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS entity_attributes (
    entity_id   TEXT NOT NULL,
    attr_key    TEXT NOT NULL,
    attr_value  TEXT NOT NULL,
    PRIMARY KEY (entity_id, attr_key)
);

CREATE INDEX IF NOT EXISTS idx_entity_attributes_entity_id ON entity_attributes(entity_id);

--------------------------------------------------------------------------------
-- profile_metadata
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profile_metadata (
    profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (profile_id, key)
);

CREATE INDEX IF NOT EXISTS idx_profile_metadata_profile_id ON profile_metadata(profile_id);

--------------------------------------------------------------------------------
-- profile_grants
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profile_grants (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    role_keys   TEXT NOT NULL DEFAULT '',
    granted_by  TEXT,
    expires_at  TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (project_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_profile_grants_profile_id ON profile_grants(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_grants_project_id ON profile_grants(project_id);

--------------------------------------------------------------------------------
-- devices
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS devices (
    id                TEXT PRIMARY KEY,
    profile_id        TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    display_name      TEXT,
    device_type       TEXT NOT NULL DEFAULT 'desktop',
    os_info           TEXT,
    assurance         TEXT NOT NULL DEFAULT 'unknown',
    trusted           INTEGER NOT NULL DEFAULT 0,
    hardware_attested INTEGER NOT NULL DEFAULT 0,
    fingerprint_hash  TEXT,
    last_ip_geo       TEXT,
    first_seen_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_devices_profile_id ON devices(profile_id);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(profile_id, fingerprint_hash);

--------------------------------------------------------------------------------
-- device_authorization_codes
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS device_authorization_codes (
    id                TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL,
    device_code_hash  BLOB NOT NULL,
    user_code         TEXT NOT NULL,
    scope             TEXT,
    status            TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'authorized', 'denied', 'expired', 'redeemed')),
    authorized_by     TEXT REFERENCES profiles(id) ON DELETE SET NULL,
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    interval_secs     INTEGER NOT NULL DEFAULT 5,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at        TEXT NOT NULL,
    authorized_at     TEXT,
    last_polled_at    TEXT,
    redeemed_session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
    -- The resource the device requested a token for (RFC 8707).
    resource_id       TEXT NOT NULL REFERENCES protected_resources(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_auth_device_code_hash ON device_authorization_codes(device_code_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_auth_user_code ON device_authorization_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_auth_expires_at ON device_authorization_codes(expires_at) WHERE status = 'pending';

--------------------------------------------------------------------------------
-- upstream_providers
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS upstream_providers (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE,
    protocol                TEXT NOT NULL CHECK (protocol IN ('oidc', 'oauth2')),
    trust_category          TEXT NOT NULL DEFAULT 'social'
                            CHECK (trust_category IN ('social', 'corporate', 'government', 'financial')),
    enabled                 INTEGER NOT NULL DEFAULT 1,
    client_id               TEXT NOT NULL,
    client_secret           BLOB NOT NULL,
    discovery_url           TEXT,
    authorization_endpoint  TEXT,
    token_endpoint          TEXT,
    userinfo_endpoint       TEXT,
    scopes                  TEXT NOT NULL DEFAULT '["openid","profile","email"]',
    show_on_login           INTEGER NOT NULL DEFAULT 1,
    display_order           INTEGER NOT NULL DEFAULT 0,
    logo_url                TEXT,
    revision                INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_upstream_providers_enabled ON upstream_providers(enabled) WHERE enabled = 1;

--------------------------------------------------------------------------------
-- upstream_identities
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS upstream_identities (
    id                TEXT PRIMARY KEY,
    profile_id        TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    provider_id       TEXT NOT NULL REFERENCES upstream_providers(id) ON DELETE CASCADE,
    upstream_subject  TEXT NOT NULL,
    upstream_issuer   TEXT,
    upstream_email    TEXT,
    upstream_name     TEXT,
    upstream_picture  TEXT,
    linked_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_login_at     TEXT,
    login_count       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(profile_id, provider_id),
    UNIQUE(provider_id, upstream_subject)
);

CREATE INDEX IF NOT EXISTS idx_upstream_identities_profile ON upstream_identities(profile_id);

--------------------------------------------------------------------------------
-- personal_access_tokens
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id            TEXT PRIMARY KEY,
    profile_id    TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT,
    token_hash    TEXT NOT NULL,
    token_prefix  TEXT NOT NULL,
    scopes        TEXT NOT NULL DEFAULT '',
    ip_allowlist  TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    expires_at    TEXT,
    last_used_at  TEXT,
    last_used_ip  TEXT,
    use_count     INTEGER NOT NULL DEFAULT 0,
    revoked_at    TEXT,
    revoked_by    TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pat_token_hash ON personal_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_pat_profile_status ON personal_access_tokens(profile_id, status);

--------------------------------------------------------------------------------
-- machine_users
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS machine_users (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    machine_type        TEXT NOT NULL DEFAULT 'service'
                        CHECK (machine_type IN ('service', 'bot', 'agent')),
    owner_type          TEXT NOT NULL DEFAULT 'profile'
                        CHECK (owner_type IN ('profile', 'organization', 'system')),
    owner_id            TEXT NOT NULL,
    client_id           TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL,
    description         TEXT,
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'suspended', 'expired', 'deleted')),
    scopes              TEXT NOT NULL DEFAULT '',
    ip_allowlist        TEXT NOT NULL DEFAULT '',
    rate_limit_rpm      INTEGER NOT NULL DEFAULT 0,
    max_token_lifetime  INTEGER,
    last_used_at        TEXT,
    expires_at          TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_machine_users_project ON machine_users(project_id);
CREATE INDEX IF NOT EXISTS idx_machine_users_owner ON machine_users(owner_type, owner_id);

--------------------------------------------------------------------------------
-- machine_user_credentials
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS machine_user_credentials (
    kid             TEXT PRIMARY KEY,
    machine_user_id TEXT NOT NULL REFERENCES machine_users(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL
                    CHECK (credential_type IN ('client_secret', 'private_key_jwt', 'mtls', 'workload_identity')),
    credential_data TEXT NOT NULL,
    algorithm       TEXT,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'grace_period', 'expired', 'revoked')),
    expires_at      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_machine_creds_user ON machine_user_credentials(machine_user_id);

--------------------------------------------------------------------------------
-- impersonation_grants
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS impersonation_grants (
    id              TEXT PRIMARY KEY,
    machine_user_id TEXT NOT NULL REFERENCES machine_users(id) ON DELETE CASCADE,
    target_type     TEXT NOT NULL CHECK (target_type IN ('role', 'user')),
    target          TEXT NOT NULL,
    allowed_scopes  TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(machine_user_id, target_type, target)
);

CREATE INDEX IF NOT EXISTS idx_impersonation_machine ON impersonation_grants(machine_user_id);

--------------------------------------------------------------------------------
-- principal_quarantine
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS principal_quarantine (
    principal_hash   TEXT PRIMARY KEY,
    principal_type   TEXT NOT NULL,
    quarantine_until TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_principal_quarantine_until ON principal_quarantine(quarantine_until);

--------------------------------------------------------------------------------
-- closure_requests
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS closure_requests (
    profile_id       TEXT PRIMARY KEY REFERENCES profiles(id),
    mode             TEXT NOT NULL
                     CHECK (mode IN ('voluntary', 'gdpr_erasure', 'admin_termination', 'regulatory_order')),
    closure_reason   TEXT,
    requested_by     TEXT NOT NULL,
    requested_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    grace_period_end TEXT,
    export_status    TEXT NOT NULL DEFAULT 'not_started'
                     CHECK (export_status IN ('not_started', 'preparing', 'ready', 'downloaded', 'expired')),
    cancel_count     INTEGER NOT NULL DEFAULT 0,
    legal_hold       TEXT
);

--------------------------------------------------------------------------------
-- export_jobs
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS export_jobs (
    id              TEXT PRIMARY KEY,
    profile_id      TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    format          TEXT NOT NULL CHECK (format IN ('json')),
    status          TEXT NOT NULL
                    CHECK (status IN ('not_started', 'preparing', 'ready', 'downloaded', 'expired')),
    archive_path    TEXT,
    size_bytes      INTEGER,
    checksum_sha256 TEXT,
    created_at      TEXT NOT NULL,
    ready_at        TEXT,
    expires_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_export_jobs_profile ON export_jobs(profile_id);

-- An undeliverable back-channel logout is a failed durable_work record; the
-- earlier dead-letter table goes.
DROP TABLE IF EXISTS logout_dlq;

--------------------------------------------------------------------------------
-- magic_link_sessions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS magic_link_sessions (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0,
    client_id   TEXT,
    redirect_uri TEXT,
    scopes      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_magic_link_email ON magic_link_sessions(email);
CREATE INDEX IF NOT EXISTS idx_magic_link_expires ON magic_link_sessions(expires_at);

--------------------------------------------------------------------------------
-- audit_records
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_records (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    chain_id    TEXT NOT NULL,
    sequence    INTEGER NOT NULL,
    actor_id    TEXT NOT NULL,
    actor_type  TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    ip_address  TEXT,
    device_id   TEXT,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL,
    UNIQUE (chain_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_id ON audit_records(chain_id, sequence);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_records(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_records(action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_records(actor_id);

--------------------------------------------------------------------------------
-- audit_chain_heads
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_chain_heads (
    chain_id        TEXT PRIMARY KEY,
    last_record_id  TEXT NOT NULL,
    last_hash       TEXT NOT NULL,
    sequence        INTEGER NOT NULL
);

-- Where a chain resumes after retention removed its oldest records.
CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
    chain_id    TEXT PRIMARY KEY,
    sequence    INTEGER NOT NULL CHECK (sequence > 0),
    hash        TEXT NOT NULL,
    cut_before  TEXT NOT NULL
);

-- Audit records are append-only: never updated, and deleted only by a
-- retention cut, which first records the cut as a checkpoint.
CREATE TRIGGER IF NOT EXISTS trg_audit_records_no_update
BEFORE UPDATE ON audit_records
BEGIN
    SELECT RAISE(ABORT, 'audit records are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_records_no_delete
BEFORE DELETE ON audit_records
WHEN OLD.timestamp >= COALESCE((SELECT MAX(cut_before) FROM audit_chain_checkpoints), '')
BEGIN
    SELECT RAISE(ABORT, 'audit records are removed only by retention');
END;

--------------------------------------------------------------------------------
-- branding_configs
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS branding_configs (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'published', 'archived')),
    data            TEXT NOT NULL,
    revision        INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_branding_configs_project_status
    ON branding_configs(project_id, status);

-- Only one published config per project.
CREATE UNIQUE INDEX IF NOT EXISTS idx_branding_configs_published
    ON branding_configs(project_id) WHERE status = 'published';

--------------------------------------------------------------------------------
-- flow_configs, flow_actions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS flow_configs (
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    flow_type   TEXT NOT NULL,
    data        TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (project_id, flow_type)
);

CREATE TABLE IF NOT EXISTS flow_actions (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    flow_type     TEXT NOT NULL,
    action_point  TEXT NOT NULL,
    action_order  INTEGER NOT NULL DEFAULT 0,
    data          TEXT NOT NULL,
    revision      INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flow_actions_project_flow
    ON flow_actions(project_id, flow_type, action_point, action_order);

--------------------------------------------------------------------------------
-- consents, claim_grants
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS consents (
    id              TEXT PRIMARY KEY,
    profile_id      TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL,
    status          TEXT NOT NULL
                        CHECK (status IN ('requested', 'active', 'revoked', 'expired')),
    consented_at    TEXT NOT NULL,
    revoked_at      TEXT,
    updated_at      TEXT NOT NULL,
    UNIQUE (profile_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_consents_client ON consents(client_id);

CREATE TABLE IF NOT EXISTS claim_grants (
    id              TEXT PRIMARY KEY,
    consent_id      TEXT NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    claim_name      TEXT NOT NULL,
    claim_type      TEXT NOT NULL CHECK (claim_type IN ('data', 'attestation')),
    granted_at      TEXT NOT NULL,
    revoked_at      TEXT,
    UNIQUE (consent_id, claim_name)
);

--------------------------------------------------------------------------------
-- invites, registration_sources
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS invites (
    id              TEXT PRIMARY KEY,
    code            TEXT NOT NULL,
    created_by      TEXT NOT NULL REFERENCES profiles(id),
    created_by_name TEXT NOT NULL,
    metadata        TEXT NOT NULL,
    max_uses        INTEGER NOT NULL CHECK (max_uses >= 0),
    use_count       INTEGER NOT NULL CHECK (use_count >= 0),
    expires_at      TEXT,
    active          INTEGER NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_code ON invites (UPPER(code));
DROP INDEX IF EXISTS idx_invites_created;
CREATE INDEX IF NOT EXISTS idx_invites_created_id ON invites (created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS registration_sources (
    profile_id      TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    source_type     TEXT NOT NULL CHECK (source_type IN (
                        'self_signup', 'invite', 'admin_created',
                        'scim_provisioned', 'federation', 'identity_brokered')),
    source_id       TEXT NOT NULL,
    referrer_id     TEXT REFERENCES profiles(id),
    utm_source      TEXT NOT NULL,
    utm_medium      TEXT NOT NULL,
    utm_campaign    TEXT NOT NULL,
    utm_term        TEXT NOT NULL,
    utm_content     TEXT NOT NULL,
    client_id       TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registration_sources_type_date
    ON registration_sources (source_type, created_at DESC);

--------------------------------------------------------------------------------
-- access_requests, notification_preferences
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS access_requests (
    id                       TEXT PRIMARY KEY,
    requester_id             TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    project_id               TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role_key                 TEXT NOT NULL,
    justification            TEXT,
    requested_duration_hours INTEGER CHECK (requested_duration_hours >= 0),
    status                   TEXT NOT NULL CHECK (status IN (
                                 'pending', 'approved', 'denied', 'cancelled', 'expired')),
    reviewed_by              TEXT REFERENCES profiles(id),
    review_comment           TEXT,
    created_at               TEXT NOT NULL,
    reviewed_at              TEXT,
    expires_at               TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);

CREATE TABLE IF NOT EXISTS device_attestations (
    id                      TEXT PRIMARY KEY,
    device_id               TEXT NOT NULL UNIQUE,
    profile_id              TEXT NOT NULL,
    format                  TEXT NOT NULL,
    key_storage             TEXT NOT NULL,
    status                  TEXT NOT NULL,
    device_public_key       BLOB NOT NULL,
    attestation_object      BLOB,
    attestation_certificate BLOB,
    aaguid                  TEXT,
    credential_id           TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    revoked_at              TEXT
);

CREATE INDEX IF NOT EXISTS idx_device_attestations_profile_id
    ON device_attestations (profile_id);

CREATE TABLE IF NOT EXISTS anomaly_events (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    profile_id  TEXT NOT NULL,
    ip_address  TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    reaction    TEXT NOT NULL,
    timestamp   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_timestamp ON anomaly_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_rule_id ON anomaly_events (rule_id);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip              TEXT PRIMARY KEY,
    failed_count    INTEGER NOT NULL DEFAULT 0,
    success_count   INTEGER NOT NULL DEFAULT 0,
    score           REAL NOT NULL DEFAULT 0.0,
    first_seen_at   TEXT NOT NULL,
    last_failed_at  TEXT,
    last_success_at TEXT,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_reputation_score ON ip_reputation (score DESC);

CREATE TABLE IF NOT EXISTS ip_allowlist_entries (
    cidr        TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profile_locations (
    profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    country     TEXT NOT NULL,
    latitude    REAL NOT NULL,
    longitude   REAL NOT NULL,
    login_count INTEGER NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    designated  INTEGER NOT NULL,
    PRIMARY KEY (profile_id, country)
);

CREATE INDEX IF NOT EXISTS idx_sessions_device_lookup
    ON sessions (profile_id, device_id, created_at DESC) WHERE device_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS password_reset_sessions (
    id              TEXT PRIMARY KEY,
    profile_id      TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'completed', 'expired')),
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    verified_at     TEXT,
    completed_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_password_reset_sessions_profile
    ON password_reset_sessions (profile_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scim_outbound_targets (
    id                TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL,
    project_id        TEXT NOT NULL REFERENCES projects(id),
    display_name      TEXT NOT NULL,
    endpoint_url      TEXT NOT NULL,
    auth_config       TEXT NOT NULL,
    attribute_mapping TEXT NOT NULL,
    group_push        TEXT NOT NULL,
    sync_config       TEXT NOT NULL,
    enabled           INTEGER NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scim_outbound_targets_project
    ON scim_outbound_targets (project_id);

CREATE TABLE IF NOT EXISTS scim_outbound_records (
    target_id       TEXT NOT NULL REFERENCES scim_outbound_targets(id) ON DELETE CASCADE,
    sid_entity_id   TEXT NOT NULL,
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('user', 'group')),
    downstream_id   TEXT NOT NULL,
    last_synced_at  TEXT NOT NULL,
    last_error      TEXT,
    failure_count   INTEGER NOT NULL CHECK (failure_count >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (target_id, sid_entity_id, entity_type)
);

CREATE TABLE IF NOT EXISTS scim_outbound_dlq (
    id              TEXT PRIMARY KEY,
    target_id       TEXT NOT NULL REFERENCES scim_outbound_targets(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    payload         TEXT NOT NULL,
    sid_entity_id   TEXT NOT NULL,
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('user', 'group')),
    error           TEXT NOT NULL,
    attempts        INTEGER NOT NULL CHECK (attempts >= 0),
    first_attempt   TEXT NOT NULL,
    last_attempt    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scim_outbound_dlq_target ON scim_outbound_dlq (target_id);

CREATE TABLE IF NOT EXISTS notification_preferences (
    profile_id      TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    preferences     TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provisioning_connectors (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    direction       TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    client_id       TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('active', 'disabled', 'retired')),
    revision        INTEGER NOT NULL CHECK (revision >= 1),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_provisioning_connectors_org
    ON provisioning_connectors (org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS provisioning_credentials (
    id              TEXT PRIMARY KEY,
    connector_id    TEXT NOT NULL REFERENCES provisioning_connectors(id),
    kind            TEXT NOT NULL CHECK (kind IN ('scim_bearer', 'client_secret')),
    status          TEXT NOT NULL CHECK (status IN ('active', 'grace_period', 'expired', 'revoked')),
    verifier        TEXT NOT NULL UNIQUE,
    expires_at      TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_provisioning_credentials_connector
    ON provisioning_credentials (connector_id, created_at DESC);
"#;
