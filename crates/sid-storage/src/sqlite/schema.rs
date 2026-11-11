// SPDX-License-Identifier: AGPL-3.0-only
//! The SQLite schema of a database file.
//!
//! A schema change edits this schema in place, which changes its version
//! ([`super::migrations::version_of`]), and a file of another version is
//! recreated, not migrated. Foreign keys and WAL are connection options, not
//! part of it.
//!
//! Every table is STRICT, so a column holds only its declared storage class.
//! A UUID is a 16-byte BLOB, checked for its length, in keys, references and
//! indexes alike.

/// Every table, index and constraint of the schema.
pub(crate) const SCHEMA: &str = r#"
-- StructuredID CE — SQLite schema

--------------------------------------------------------------------------------
-- profiles
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profiles (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
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
    manager_id      BLOB CHECK (length(manager_id) = 16) REFERENCES profiles(id) ON DELETE SET NULL,
    migration_pending       INTEGER NOT NULL DEFAULT 0,
    migration_started_at    TEXT,
    migration_completed_at  TEXT,
    revision        INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_profiles_username ON profiles(username);
CREATE INDEX IF NOT EXISTS idx_profiles_status ON profiles(status);
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
    id                  BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id          BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
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
) STRICT;

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
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id      BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT 'personal',
    custom_label    TEXT,
    is_primary      INTEGER NOT NULL DEFAULT 0,
    verified        INTEGER NOT NULL DEFAULT 0,
    verified_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

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
    id                  BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id          BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
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
    last_used_at        TEXT,
    -- The artifact a policy verdict was verified against.
    zkpp_artifact       BLOB CHECK (length(zkpp_artifact) = 32)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_credentials_profile_id ON credentials(profile_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_credentials_profile_type ON credentials(profile_id, credential_type);
-- A profile has one password: at most one active OPAQUE credential.
CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_active_opaque
    ON credentials(profile_id) WHERE credential_type = 'opaque' AND status = 'active';

-- SQLite cannot add a table constraint across these columns by name: triggers
-- refuse a row whose policy evidence disagrees.
CREATE TRIGGER IF NOT EXISTS credentials_policy_evidence_insert
BEFORE INSERT ON credentials
WHEN NOT ((NEW.zkpp_verified <> 0 AND NEW.policy_version IS NOT NULL AND NEW.zkpp_artifact IS NOT NULL)
       OR (NEW.zkpp_verified = 0 AND NEW.policy_version IS NULL AND NEW.zkpp_artifact IS NULL))
BEGIN
    SELECT RAISE(ABORT, 'credential policy evidence');
END;

CREATE TRIGGER IF NOT EXISTS credentials_policy_evidence_update
BEFORE UPDATE OF zkpp_verified, policy_version, zkpp_artifact ON credentials
WHEN NOT ((NEW.zkpp_verified <> 0 AND NEW.policy_version IS NOT NULL AND NEW.zkpp_artifact IS NOT NULL)
       OR (NEW.zkpp_verified = 0 AND NEW.policy_version IS NULL AND NEW.zkpp_artifact IS NULL))
BEGIN
    SELECT RAISE(ABORT, 'credential policy evidence');
END;

CREATE TABLE IF NOT EXISTS webauthn_user_handles (
    profile_id  BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles (id) ON DELETE CASCADE,
    rp_id       TEXT NOT NULL,
    user_handle BLOB NOT NULL CHECK (length(user_handle) = 16),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (profile_id, rp_id),
    UNIQUE (rp_id, user_handle)
) STRICT;

--------------------------------------------------------------------------------
-- password history: per-owner epochs with
-- sealed VOPRF keys, and the KSF outputs of accepted passwords. History
-- belongs to the owner and outlives any credential row.
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS password_histories (
    owner_id    BLOB PRIMARY KEY CHECK (length(owner_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    revision    INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE IF NOT EXISTS password_history_epochs (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    owner_id        BLOB NOT NULL CHECK (length(owner_id) = 16) REFERENCES password_histories(owner_id) ON DELETE CASCADE,
    suite           TEXT NOT NULL CHECK (suite IN ('pallas-poseidon-v1')),
    public_key      BLOB NOT NULL CHECK (length(public_key) = 32),
    ksf_memory_kib  INTEGER NOT NULL CHECK (ksf_memory_kib > 0),
    ksf_passes      INTEGER NOT NULL CHECK (ksf_passes > 0),
    ksf_lanes       INTEGER NOT NULL CHECK (ksf_lanes > 0),
    ksf_salt        BLOB NOT NULL CHECK (length(ksf_salt) = 32),
    status          TEXT NOT NULL CHECK (status IN ('active', 'compare_only', 'retired')),
    created_at      TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS password_history_one_active_epoch
    ON password_history_epochs (owner_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS password_history_entries (
    epoch_id        BLOB NOT NULL CHECK (length(epoch_id) = 16) REFERENCES password_history_epochs(id) ON DELETE CASCADE,
    owner_id        BLOB NOT NULL CHECK (length(owner_id) = 16) REFERENCES password_histories(owner_id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    entry           BLOB NOT NULL CHECK (length(entry) = 32),
    operation_id    BLOB NOT NULL CHECK (length(operation_id) = 16),
    policy_version  INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (epoch_id, seq)
) STRICT;

CREATE INDEX IF NOT EXISTS password_history_entries_owner
    ON password_history_entries (owner_id, seq);

CREATE TABLE IF NOT EXISTS password_history_write_cutoff (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    not_before TEXT
) STRICT;
INSERT OR IGNORE INTO password_history_write_cutoff (singleton) VALUES (1);

--------------------------------------------------------------------------------
-- The history evaluator's own store, keyed by the owner's history input domain.
-- An embedded file keeps it beside the credential data.
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS history_key_write_cutoff (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    not_before TEXT
) STRICT;
INSERT OR IGNORE INTO history_key_write_cutoff (singleton) VALUES (1);

CREATE TABLE IF NOT EXISTS history_key_epochs (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    owner_domain    BLOB NOT NULL CHECK (length(owner_domain) = 32),
    suite           TEXT NOT NULL CHECK (suite IN ('pallas-poseidon-v1')),
    public_key      BLOB NOT NULL CHECK (length(public_key) = 32),
    wrapped_key     BLOB NOT NULL,
    ksf_memory_kib  INTEGER NOT NULL CHECK (ksf_memory_kib > 0),
    ksf_passes      INTEGER NOT NULL CHECK (ksf_passes > 0),
    ksf_lanes       INTEGER NOT NULL CHECK (ksf_lanes > 0),
    ksf_salt        BLOB NOT NULL CHECK (length(ksf_salt) = 32),
    status          TEXT NOT NULL CHECK (status IN ('active', 'compare_only', 'retired')),
    created_at      TEXT NOT NULL,
    -- The first enrollment operation that made it, if any.
    created_by      BLOB CHECK (length(created_by) = 16)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS history_key_one_active_epoch
    ON history_key_epochs (owner_domain) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS history_key_epochs_owner ON history_key_epochs (owner_domain);

CREATE INDEX IF NOT EXISTS history_key_epochs_created_by
    ON history_key_epochs (created_by) WHERE created_by IS NOT NULL;

CREATE TABLE IF NOT EXISTS history_key_abandoned (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    owner_domain BLOB NOT NULL CHECK (length(owner_domain) = 32),
    abandoned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE IF NOT EXISTS history_key_lifecycle (
    owner_domain BLOB PRIMARY KEY CHECK (length(owner_domain) = 32),
    revision     INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;

-- The live epochs the lifecycle revision of an owner recorded.
CREATE TABLE IF NOT EXISTS history_key_live (
    owner_domain BLOB NOT NULL REFERENCES history_key_lifecycle(owner_domain) ON DELETE CASCADE,
    epoch_id     BLOB NOT NULL CHECK (length(epoch_id) = 16),
    PRIMARY KEY (owner_domain, epoch_id)
) STRICT;

CREATE TABLE IF NOT EXISTS history_key_replaced (
    epoch_id             BLOB PRIMARY KEY CHECK (length(epoch_id) = 16) REFERENCES history_key_epochs(id) ON DELETE CASCADE,
    owner_domain         BLOB NOT NULL CHECK (length(owner_domain) = 32),
    replaced_at_revision INTEGER NOT NULL CHECK (replaced_at_revision > 0)
) STRICT;

CREATE TABLE IF NOT EXISTS history_key_uses (
    operation_id BLOB NOT NULL CHECK (length(operation_id) = 16),
    epoch_id     BLOB NOT NULL CHECK (length(epoch_id) = 16) REFERENCES history_key_epochs(id) ON DELETE CASCADE,
    owner_domain BLOB NOT NULL CHECK (length(owner_domain) = 32),
    expires_at   TEXT NOT NULL,
    PRIMARY KEY (operation_id, epoch_id)
) STRICT;

CREATE INDEX IF NOT EXISTS history_key_uses_owner ON history_key_uses (owner_domain, epoch_id);

CREATE TABLE IF NOT EXISTS history_key_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor_id    TEXT NOT NULL,
    actor_type  TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    metadata    TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS history_key_versions (
    version    INTEGER PRIMARY KEY CHECK (version > 0),
    salt       BLOB NOT NULL,
    algorithm  TEXT NOT NULL,
    context    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE IF NOT EXISTS history_key_purged (
    owner_domain BLOB PRIMARY KEY CHECK (length(owner_domain) = 32),
    purged_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

--------------------------------------------------------------------------------
-- sessions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sessions (
    id                BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id        BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    client_id         TEXT,
    device_id         BLOB CHECK (length(device_id) = 16),
    ip_address        BLOB CHECK (length(ip_address) IN (4, 16)),
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
    authenticated_by  BLOB CHECK (length(authenticated_by) = 16) REFERENCES sessions(id) ON DELETE SET NULL,
    -- The CSRF token a browser session carries.
    browser_csrf      BLOB,
    CHECK ((elevation_level IS NULL AND elevation_until IS NULL)
        OR (elevation_level IN ('elevated', 'critical') AND elevation_until IS NOT NULL))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sessions_profile_id ON sessions(profile_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_client_id ON sessions(client_id) WHERE client_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_authenticated_by ON sessions(authenticated_by) WHERE authenticated_by IS NOT NULL;

--------------------------------------------------------------------------------
-- principals
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS principals (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    principal_type  TEXT NOT NULL,
    value           TEXT NOT NULL,
    verified        INTEGER NOT NULL DEFAULT 0,
    verified_at     TEXT,
    verification_expires TEXT,
    assigned_profile_id BLOB CHECK (length(assigned_profile_id) = 16),
    assignment_revision INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- The email policy revision an email key was written under.
    email_policy_revision INTEGER
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_principals_type_value ON principals(principal_type, value);
CREATE INDEX IF NOT EXISTS idx_principals_value ON principals(value);
CREATE INDEX IF NOT EXISTS idx_principals_assigned ON principals(assigned_profile_id);

CREATE TABLE IF NOT EXISTS email_policy_activations (
    scope        TEXT PRIMARY KEY,
    revision     INTEGER NOT NULL CHECK (revision > 0),
    activated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;
INSERT OR IGNORE INTO email_policy_activations (scope, revision) VALUES ('installation', 1);

CREATE TABLE IF NOT EXISTS email_policy_dispositions (
    -- Deferred: a restored quarantined key's record precedes the key.
    principal_id  BLOB PRIMARY KEY CHECK (length(principal_id) = 16)
                  REFERENCES principals (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    from_revision INTEGER NOT NULL,
    to_revision   INTEGER NOT NULL,
    disposition   TEXT NOT NULL CHECK (disposition IN ('migrated', 'quarantined')),
    reason        TEXT NOT NULL,
    recorded_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

-- An email key is written only under the active revision, except a key
-- restored with its quarantine from its own revision to the active one.
CREATE TRIGGER IF NOT EXISTS principals_email_policy_insert
BEFORE INSERT ON principals
WHEN (NEW.principal_type = 'email') <> (NEW.email_policy_revision IS NOT NULL)
  OR (NEW.principal_type = 'email'
      AND NEW.email_policy_revision IS NOT
          (SELECT revision FROM email_policy_activations WHERE scope = 'installation')
      AND NOT EXISTS (SELECT 1 FROM email_policy_dispositions d
                      WHERE d.principal_id = NEW.id
                        AND d.disposition = 'quarantined'
                        AND d.from_revision = NEW.email_policy_revision
                        AND d.to_revision =
                            (SELECT revision FROM email_policy_activations
                             WHERE scope = 'installation')))
BEGIN
    SELECT RAISE(ABORT, 'email policy fence');
END;

CREATE TRIGGER IF NOT EXISTS principals_email_policy_update
BEFORE UPDATE OF value, email_policy_revision, principal_type ON principals
WHEN (NEW.principal_type = 'email') <> (NEW.email_policy_revision IS NOT NULL)
  OR (NEW.principal_type = 'email'
      AND (NEW.value IS NOT OLD.value
           OR NEW.email_policy_revision IS NOT OLD.email_policy_revision)
      AND NEW.email_policy_revision IS NOT
          (SELECT revision FROM email_policy_activations WHERE scope = 'installation'))
BEGIN
    SELECT RAISE(ABORT, 'email policy fence');
END;

CREATE TABLE IF NOT EXISTS principal_bindings (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    principal_id    BLOB NOT NULL CHECK (length(principal_id) = 16) REFERENCES principals(id) ON DELETE CASCADE,
    profile_id      BLOB NOT NULL CHECK (length(profile_id) = 16),
    is_primary      INTEGER NOT NULL DEFAULT 0,
    source_field    TEXT,
    source_email_id BLOB CHECK (length(source_email_id) = 16) REFERENCES profile_emails(id) ON DELETE SET NULL,
    source_phone_id BLOB CHECK (length(source_phone_id) = 16) REFERENCES profile_phones(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (principal_id, profile_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_principal_bindings_principal_id ON principal_bindings(principal_id);
CREATE INDEX IF NOT EXISTS idx_principal_bindings_profile ON principal_bindings(profile_id);

--------------------------------------------------------------------------------
-- projects
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS projects (
    id          BLOB PRIMARY KEY CHECK (length(id) = 16),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner_id    BLOB CHECK (length(owner_id) = 16) REFERENCES profiles(id) ON DELETE SET NULL,
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id) WHERE owner_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS update_projects_updated_at
    AFTER UPDATE ON projects
    FOR EACH ROW
    BEGIN
        UPDATE projects SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
    END;

-- Default system project: the nil UUID.
INSERT OR IGNORE INTO projects (id, name, description, is_system)
VALUES (X'00000000000000000000000000000000', 'SID', 'Default system project', 1);

--------------------------------------------------------------------------------
-- applications: the container of a client role, a resource role, or both
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS applications (
    id          BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id  BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id),
    name        TEXT NOT NULL,
    -- The installation's own integration this is; each exists at most once.
    system_integration TEXT UNIQUE,
    revision    INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    -- Target of the composite key below: a role's project is its application's.
    UNIQUE (id, project_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id);

--------------------------------------------------------------------------------
-- oauth2_clients
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oauth2_clients (
    client_id                           TEXT PRIMARY KEY,
    -- One client role per application, in the application's project.
    application_id                      BLOB NOT NULL UNIQUE CHECK (length(application_id) = 16),
    -- The resource a token is for when a request names none.
    default_resource                    BLOB CHECK (length(default_resource) = 16) REFERENCES protected_resources(id),
    client_secret_hash                  BLOB,
    -- Public keys of a private_key_jwt client: a JWK Set as JSON text.
    jwks                                TEXT,
    -- Redirect URIs: a JSON array of strings (a URI may hold a comma).
    redirect_uris                       TEXT NOT NULL DEFAULT '[]',
    allowed_scopes                      TEXT NOT NULL DEFAULT 'openid profile email',
    grant_types                         TEXT NOT NULL DEFAULT 'authorization_code',
    client_name                         TEXT NOT NULL,
    active                              INTEGER NOT NULL DEFAULT 1,
    project_id                          BLOB NOT NULL DEFAULT X'00000000000000000000000000000000'
                                        CHECK (length(project_id) = 16) REFERENCES projects(id),
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
    registration_iat                    BLOB CHECK (length(registration_iat) = 16),
    registration_access_token_hash      BLOB,
    login_strategy                      TEXT NOT NULL DEFAULT 'local_first',
    show_federation_button              INTEGER NOT NULL DEFAULT 1,
    federation_timeout_ms               INTEGER NOT NULL DEFAULT 500,
    unified_input                       INTEGER NOT NULL DEFAULT 0,
    org_id                              BLOB CHECK (length(org_id) = 16) REFERENCES organizations(id),
    revision                            INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at                          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (application_id, project_id) REFERENCES applications (id, project_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_project ON oauth2_clients(project_id);

-- Protected-resource roles. A row is never deleted: removing its application
-- retires it (application_id NULL), so its indicator is never given to
-- another resource of the issuer.
CREATE TABLE IF NOT EXISTS protected_resources (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    application_id  BLOB UNIQUE CHECK (length(application_id) = 16) REFERENCES applications(id),
    issuer_id       BLOB NOT NULL CHECK (length(issuer_id) = 16) REFERENCES oidc_issuers(id),
    indicator       TEXT NOT NULL,
    scopes          TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL CHECK (state IN ('active', 'inactive', 'retired')),
    revision        INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (issuer_id, indicator),
    CHECK ((state = 'retired') = (application_id IS NULL))
) STRICT;

-- Explicit permission of one client to obtain tokens for one resource. The
-- client is an OAuth client or a machine user; `client_id` is its identifier
-- either way. SQLite keys a generated column by a unique index, not a
-- primary key.
CREATE TABLE IF NOT EXISTS resource_access (
    oauth_client_id    TEXT REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    machine_client_id  TEXT REFERENCES machine_users(client_id) ON DELETE CASCADE,
    client_id          TEXT NOT NULL
                       GENERATED ALWAYS AS (COALESCE(oauth_client_id, machine_client_id)) STORED,
    resource_id        BLOB NOT NULL CHECK (length(resource_id) = 16) REFERENCES protected_resources(id),
    scopes             TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    CHECK ((oauth_client_id IS NULL) != (machine_client_id IS NULL))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_resource_access_client
    ON resource_access(client_id, resource_id);

CREATE INDEX IF NOT EXISTS idx_resource_access_resource ON resource_access(resource_id);

--------------------------------------------------------------------------------
-- refresh_tokens
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BLOB PRIMARY KEY CHECK (length(id) = 16),
    token_hash  BLOB NOT NULL UNIQUE,
    session_id  BLOB NOT NULL CHECK (length(session_id) = 16) REFERENCES sessions(id) ON DELETE CASCADE,
    profile_id  BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '',
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked     INTEGER NOT NULL DEFAULT 0,
    replaced_by BLOB CHECK (length(replaced_by) = 16),
    family_id   BLOB NOT NULL CHECK (length(family_id) = 16),
    grace_expires_at TEXT,
    -- JWK thumbprint of the DPoP key the token is bound to.
    dpop_jkt    TEXT,
    -- The resource the grant was issued for (RFC 8707).
    resource_id BLOB NOT NULL CHECK (length(resource_id) = 16) REFERENCES protected_resources(id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_profile ON refresh_tokens(profile_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);

--------------------------------------------------------------------------------
-- native_generations: the refresh credentials of a native session, one
-- generation at a time, bound to its application key. A rotated generation
-- keeps the exchange that rotated it, its successor and, until the successor
-- is used, the sealed result a retry of that exchange receives until
-- redeliver_until.
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS native_generations (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    session_id      BLOB NOT NULL CHECK (length(session_id) = 16) REFERENCES sessions(id) ON DELETE CASCADE,
    key_jkt         TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    exchange        BLOB CHECK (exchange IS NULL OR length(exchange) = 16),
    successor_id    BLOB CHECK (length(successor_id) = 16),
    redeliver_until TEXT,
    sealed          BLOB,
    CHECK ((exchange IS NULL) = (successor_id IS NULL)),
    CHECK ((exchange IS NULL) = (redeliver_until IS NULL)),
    CHECK (sealed IS NULL OR exchange IS NOT NULL)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_native_generations_session ON native_generations(session_id);
-- A generation's predecessor, found by every rotation; a generation has at
-- most one.
CREATE UNIQUE INDEX IF NOT EXISTS idx_native_generations_successor
    ON native_generations(successor_id) WHERE successor_id IS NOT NULL;

-- One row per credential of a generation: its SHA-256, never the credential.
CREATE TABLE IF NOT EXISTS native_credentials (
    credential_hash BLOB PRIMARY KEY,
    generation_id   BLOB NOT NULL CHECK (length(generation_id) = 16) REFERENCES native_generations(id) ON DELETE CASCADE
) STRICT;

CREATE INDEX IF NOT EXISTS idx_native_credentials_generation ON native_credentials(generation_id);

--------------------------------------------------------------------------------
-- authorization_codes
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash       BLOB PRIMARY KEY,
    profile_id      BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
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
    session_id      BLOB CHECK (length(session_id) = 16),
    -- The resource the authorization was granted for (RFC 8707).
    resource_id     BLOB NOT NULL CHECK (length(resource_id) = 16) REFERENCES protected_resources(id),
    -- The authentication of the session that authorized the code, which the
    -- tokens it redeems into report.
    authorizing_session_id BLOB NOT NULL CHECK (length(authorizing_session_id) = 16)
                    REFERENCES sessions(id) ON DELETE CASCADE,
    authenticated_at TEXT NOT NULL,
    amr             TEXT NOT NULL,
    assurance_level TEXT NOT NULL CHECK (assurance_level IN ('basic', 'standard')),
    elevation_level TEXT,
    elevation_until TEXT,
    CHECK ((elevation_level IS NULL AND elevation_until IS NULL)
        OR (elevation_level IN ('elevated', 'critical') AND elevation_until IS NOT NULL))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);

--------------------------------------------------------------------------------
-- initial_access_tokens
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS initial_access_tokens (
    id                        BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id                BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    token_hash                BLOB NOT NULL UNIQUE,
    max_clients               INTEGER NOT NULL DEFAULT 0,
    clients_registered        INTEGER NOT NULL DEFAULT 0,
    allowed_scopes            TEXT NOT NULL DEFAULT '',
    allowed_grant_types       TEXT NOT NULL DEFAULT '',
    allowed_redirect_patterns TEXT NOT NULL DEFAULT '',
    created_by                BLOB NOT NULL CHECK (length(created_by) = 16),
    revoked                   INTEGER NOT NULL DEFAULT 0,
    expires_at                TEXT NOT NULL,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

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
) STRICT;

--------------------------------------------------------------------------------
-- durable_work (required work committed with its state change; fenced claims)
--------------------------------------------------------------------------------

-- The last period issued (every period through it was issued, and one with
-- no row in operation_periods is retired and never admitted again) and the
-- policy every replica issues and retires periods under: how long a period
-- accepts new commands, how long its commands are kept for retries after
-- that, how many completions one period holds and the largest result one
-- keeps.
CREATE TABLE IF NOT EXISTS operation_period_state (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    issued_through     INTEGER NOT NULL DEFAULT 0 CHECK (issued_through >= 0),
    acceptance_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (acceptance_seconds > 0),
    retention_seconds  INTEGER NOT NULL DEFAULT 86400 CHECK (retention_seconds >= 0),
    capacity           INTEGER NOT NULL DEFAULT 100000 CHECK (capacity > 0),
    result_bytes       INTEGER NOT NULL DEFAULT 65536 CHECK (result_bytes > 0)
) STRICT;
INSERT OR IGNORE INTO operation_period_state (id) VALUES (1);

-- The periods keyed commands are admitted under: issued in increasing order
-- at issued_at_ms, accepting new commands until accepted_until_ms (Unix
-- milliseconds), with the completions committed under each.
CREATE TABLE IF NOT EXISTS operation_periods (
    period            INTEGER PRIMARY KEY CHECK (period > 0),
    issued_at_ms      INTEGER NOT NULL,
    accepted_until_ms INTEGER NOT NULL,
    recorded          INTEGER NOT NULL DEFAULT 0 CHECK (recorded >= 0)
) STRICT;

-- The completion of a caller's keyed command, committed with its effect.
CREATE TABLE IF NOT EXISTS operation_results (
    namespace    TEXT NOT NULL,
    op_key       TEXT NOT NULL,
    method       TEXT NOT NULL,
    fingerprint  BLOB NOT NULL,
    result       BLOB NOT NULL,
    completed_at TEXT NOT NULL,
    -- The period a keyed command was named with; NULL for the record a
    -- ceremony keeps of its own operation.
    period       INTEGER REFERENCES operation_periods (period),
    -- Unix milliseconds past which the completion is not kept; NULL keeps it
    -- until its owner purges it.
    retain_until_ms INTEGER,
    PRIMARY KEY (namespace, op_key)
) STRICT;
CREATE INDEX IF NOT EXISTS operation_results_retain_until
    ON operation_results (retain_until_ms) WHERE retain_until_ms IS NOT NULL;
CREATE INDEX IF NOT EXISTS operation_results_period
    ON operation_results (period) WHERE period IS NOT NULL;

-- The identifier each keyed creation allocated, bound to its command. Not a
-- reference to operation_periods: a binding of a creation that never
-- completed outlives the retirement of its period, kept to reconcile what it
-- began.
CREATE TABLE IF NOT EXISTS operation_resources (
    namespace   TEXT NOT NULL,
    op_key      TEXT NOT NULL,
    method      TEXT NOT NULL,
    fingerprint BLOB NOT NULL,
    period      INTEGER,
    resource    BLOB NOT NULL,
    bound_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, op_key)
) STRICT;
CREATE INDEX IF NOT EXISTS operation_resources_period
    ON operation_resources (period) WHERE period IS NOT NULL;

-- Short-lived state a ceremony step leaves for the next, and single-use
-- admissions; live while expires_at_ms (Unix milliseconds) is ahead.
CREATE TABLE IF NOT EXISTS ceremony_states (
    namespace     TEXT NOT NULL,
    state_key     TEXT NOT NULL,
    value         BLOB NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, state_key)
) STRICT;
CREATE INDEX IF NOT EXISTS ceremony_states_expires_at
    ON ceremony_states (expires_at_ms);

-- Events counted per key in a window ending at window_ends_ms.
CREATE TABLE IF NOT EXISTS ceremony_counts (
    namespace      TEXT NOT NULL,
    count_key      TEXT NOT NULL,
    count          INTEGER NOT NULL,
    window_ends_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, count_key)
) STRICT;
CREATE INDEX IF NOT EXISTS ceremony_counts_window_ends
    ON ceremony_counts (window_ends_ms);

-- One row per background job currently held: whoever inserted the row runs
-- the job until it deletes the row or the lease runs out.
CREATE TABLE IF NOT EXISTS job_locks (
    job        INTEGER PRIMARY KEY,
    holder     TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS durable_work (
    id           BLOB PRIMARY KEY CHECK (length(id) = 16),
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
) STRICT;

-- One index per question a claim asks, each read by kind and time.
CREATE INDEX IF NOT EXISTS idx_durable_work_due
    ON durable_work (kind, not_before) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_durable_work_lease
    ON durable_work (kind, lease_until) WHERE state = 'claimed';
CREATE INDEX IF NOT EXISTS idx_durable_work_expiry
    ON durable_work (kind, expires_at)
    WHERE state IN ('pending', 'claimed') AND expires_at IS NOT NULL;

--------------------------------------------------------------------------------
-- instance_secrets (sealed secrets every replica shares; written once)
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS instance_secrets (
    name        TEXT PRIMARY KEY,
    sealed      BLOB NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE IF NOT EXISTS bootstrap_policy (
    scope      TEXT PRIMARY KEY CHECK (scope = 'installation'),
    policy     TEXT NOT NULL CHECK (policy = 'centrally_managed'),
    adopted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TRIGGER IF NOT EXISTS instance_secrets_no_claim_when_centrally_managed_insert
BEFORE INSERT ON instance_secrets
WHEN NEW.name = 'admin_claim' AND EXISTS (SELECT 1 FROM bootstrap_policy)
BEGIN
    SELECT RAISE(ABORT, 'centrally managed installation: no administrator claim');
END;

CREATE TRIGGER IF NOT EXISTS instance_secrets_no_claim_when_centrally_managed_update
BEFORE UPDATE ON instance_secrets
WHEN NEW.name = 'admin_claim' AND EXISTS (SELECT 1 FROM bootstrap_policy)
BEGIN
    SELECT RAISE(ABORT, 'centrally managed installation: no administrator claim');
END;

CREATE TABLE IF NOT EXISTS enrollment_policy (
    scope                       TEXT PRIMARY KEY CHECK (scope = 'installation'),
    mode                        TEXT NOT NULL
        CHECK (mode IN ('open', 'invite_only', 'admin_only', 'domain_restricted')),
    allowed_domains             TEXT NOT NULL DEFAULT '[]' CHECK (json_type(allowed_domains) = 'array'),
    track_source                INTEGER NOT NULL CHECK (track_source IN (0, 1)),
    invite_default_max_uses     INTEGER NOT NULL CHECK (invite_default_max_uses BETWEEN 0 AND 4294967295),
    invite_default_expiry_hours INTEGER NOT NULL CHECK (invite_default_expiry_hours BETWEEN 0 AND 4294967295),
    updated_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT enrollment_policy_domains_for_restricted_mode
        CHECK (mode <> 'domain_restricted' OR json_array_length(allowed_domains) > 0)
) STRICT;

--------------------------------------------------------------------------------
-- organizations (the installation's own organization is `is_instance`)
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS organizations (
    id                BLOB PRIMARY KEY CHECK (length(id) = 16),
    org_type          TEXT NOT NULL
        CHECK (org_type IN ('family', 'community', 'commercial', 'government')),
    status            TEXT NOT NULL
        CHECK (status IN ('pending_dns', 'pending_claim', 'active_trial', 'active',
                          'suspended', 'deprovisioning', 'deleted')),
    canonical_domain  TEXT NOT NULL,
    is_instance       INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS organizations_one_instance
    ON organizations (is_instance) WHERE is_instance;

--------------------------------------------------------------------------------
-- oidc issuers: one per issuing authority and recipient organization; a handle
-- and a canonical URL belong to one issuer forever (rows are never deleted)
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oidc_issuers (
    id                BLOB PRIMARY KEY CHECK (length(id) = 16),
    handle            TEXT NOT NULL UNIQUE,
    canonical_url     TEXT NOT NULL UNIQUE,
    authority         TEXT NOT NULL CHECK (authority IN ('local')),
    recipient_org     BLOB NOT NULL CHECK (length(recipient_org) = 16) REFERENCES organizations(id),
    created_at        TEXT NOT NULL,
    UNIQUE (authority, recipient_org)
) STRICT;

-- Token-signing keys, one row per generation; the private key only sealed.
CREATE TABLE IF NOT EXISTS oidc_issuer_signing_keys (
    issuer_id           BLOB NOT NULL CHECK (length(issuer_id) = 16) REFERENCES oidc_issuers(id),
    generation          INTEGER NOT NULL CHECK (generation >= 1),
    key_id              TEXT NOT NULL,
    public_key          BLOB NOT NULL CHECK (length(public_key) = 32),
    sealed_private_key  BLOB NOT NULL,
    created_at          TEXT NOT NULL,
    PRIMARY KEY (issuer_id, generation)
) STRICT;

-- A Profile's pairwise identity at one organization (scope): the pairwise
-- `sub` of every client of that scope, allocated on the first visit.
CREATE TABLE IF NOT EXISTS service_bindings (
    binding_id    BLOB PRIMARY KEY CHECK (length(binding_id) = 16),
    profile_id    BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    scope         TEXT NOT NULL CHECK (trim(scope) <> ''),
    binding_index INTEGER NOT NULL CHECK (binding_index >= 0),
    created_at    TEXT NOT NULL,
    last_used_at  TEXT NOT NULL,
    UNIQUE (profile_id, scope),
    UNIQUE (profile_id, binding_index)
) STRICT;

--------------------------------------------------------------------------------
-- roles
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS roles (
    id          BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id  BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
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
) STRICT;

CREATE INDEX IF NOT EXISTS idx_roles_project_id ON roles(project_id);

--------------------------------------------------------------------------------
-- groups
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS groups (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id      BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    parent_group_id BLOB CHECK (length(parent_group_id) = 16) REFERENCES groups(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(project_id, name)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_groups_project_id ON groups(project_id);
CREATE INDEX IF NOT EXISTS idx_groups_parent ON groups(parent_group_id) WHERE parent_group_id IS NOT NULL;

--------------------------------------------------------------------------------
-- group_members
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS group_members (
    group_id    BLOB NOT NULL CHECK (length(group_id) = 16) REFERENCES groups(id) ON DELETE CASCADE,
    profile_id  BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (group_id, profile_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_group_members_profile_id ON group_members(profile_id);

--------------------------------------------------------------------------------
-- role_assignments
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS role_assignments (
    id               BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id       BLOB CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    group_id         BLOB CHECK (length(group_id) = 16) REFERENCES groups(id) ON DELETE CASCADE,
    machine_user_id  BLOB CHECK (length(machine_user_id) = 16),
    -- An independent OAuth client as its own principal.
    oauth_client_id  TEXT REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    -- A provisioning connector as its own principal.
    provisioning_connector_id BLOB CHECK (length(provisioning_connector_id) = 16)
                     REFERENCES provisioning_connectors(id) ON DELETE CASCADE,
    role_id          BLOB NOT NULL CHECK (length(role_id) = 16) REFERENCES roles(id) ON DELETE CASCADE,
    scope            TEXT,
    expires_at       TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- Who created it on what authority (D050 B); absent provenance confers no
    -- delegation authority. A redelegated administrative assignment ends with
    -- its source.
    granted_by               TEXT,
    basis_assignment_id      BLOB CHECK (length(basis_assignment_id) = 16),
    depends_on_assignment_id BLOB CHECK (length(depends_on_assignment_id) = 16)
                             REFERENCES role_assignments(id) ON DELETE CASCADE,
    revision                 INTEGER NOT NULL DEFAULT 0,
    CHECK (
        (profile_id IS NOT NULL) + (group_id IS NOT NULL) + (machine_user_id IS NOT NULL)
            + (oauth_client_id IS NOT NULL) + (provisioning_connector_id IS NOT NULL) = 1
    ),
    CHECK (granted_by IS NOT NULL
           OR (basis_assignment_id IS NULL AND depends_on_assignment_id IS NULL))
) STRICT;

-- The envelope of an administrative assignment. A group recipients are
-- restricted to cannot be deleted from under it: that would widen it.
CREATE TABLE IF NOT EXISTS role_assignment_admin (
    assignment_id      BLOB PRIMARY KEY CHECK (length(assignment_id) = 16)
                       REFERENCES role_assignments(id) ON DELETE CASCADE,
    recipient_group_id BLOB CHECK (length(recipient_group_id) = 16) REFERENCES groups(id) ON DELETE RESTRICT,
    -- NULL: the envelope adds no validity limit of its own.
    max_validity_secs  INTEGER CHECK (max_validity_secs > 0)
) STRICT;

CREATE TABLE IF NOT EXISTS role_assignment_admin_entries (
    assignment_id BLOB NOT NULL CHECK (length(assignment_id) = 16)
                  REFERENCES role_assignment_admin(assignment_id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('operation', 'recipient_kind', 'permission')),
    value         TEXT NOT NULL,
    PRIMARY KEY (assignment_id, kind, value),
    CHECK (kind <> 'operation' OR value IN ('assign', 'revoke', 'edit_role', 'redelegate')),
    CHECK (kind <> 'recipient_kind'
           OR value IN ('profile', 'group', 'machine_user', 'oauth_client'))
) STRICT;

-- A deleted role leaves the envelope: that only narrows it.
CREATE TABLE IF NOT EXISTS role_assignment_admin_roles (
    assignment_id BLOB NOT NULL CHECK (length(assignment_id) = 16)
                  REFERENCES role_assignment_admin(assignment_id) ON DELETE CASCADE,
    role_id       BLOB NOT NULL CHECK (length(role_id) = 16) REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (assignment_id, role_id)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_role_assignment_admin_roles_role
    ON role_assignment_admin_roles(role_id);

CREATE TABLE IF NOT EXISTS role_assignment_policy_admin (
    assignment_id BLOB NOT NULL CHECK (length(assignment_id) = 16)
                  REFERENCES role_assignments(id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK (operation IN ('read', 'edit', 'redelegate')),
    PRIMARY KEY (assignment_id, operation)
) STRICT;

-- The permission ceiling an envelope approved a non-administrative assignment
-- under; its role is never edited past it while the assignment exists.
CREATE TABLE IF NOT EXISTS role_assignment_ceilings (
    assignment_id BLOB NOT NULL CHECK (length(assignment_id) = 16)
                  REFERENCES role_assignments(id) ON DELETE CASCADE,
    permission    TEXT NOT NULL,
    PRIMARY KEY (assignment_id, permission)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_role_assignments_oauth_client_id ON role_assignments(oauth_client_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_provisioning_connector_id
    ON role_assignments(provisioning_connector_id);

CREATE INDEX IF NOT EXISTS idx_role_assignments_profile_id ON role_assignments(profile_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_group_id ON role_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_machine_user_id ON role_assignments(machine_user_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_role_id ON role_assignments(role_id);

--------------------------------------------------------------------------------
-- cedar_policies
--------------------------------------------------------------------------------

-- A policy's scope: the installation (neither column), one project or one
-- protected resource.
CREATE TABLE IF NOT EXISTS cedar_policies (
    id          BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id  BLOB CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    resource_id BLOB CHECK (length(resource_id) = 16) REFERENCES protected_resources(id),
    name        TEXT NOT NULL,
    description TEXT,
    policy_text TEXT NOT NULL,
    effect      TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    revision    INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (project_id IS NULL OR resource_id IS NULL)
) STRICT;

-- One name per scope; SQLite keeps NULLs distinct in a UNIQUE constraint.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cedar_policies_scope_name
    ON cedar_policies(COALESCE(project_id, X''), COALESCE(resource_id, X''), name);
CREATE INDEX IF NOT EXISTS idx_cedar_policies_project_id ON cedar_policies(project_id);
CREATE INDEX IF NOT EXISTS idx_cedar_policies_resource_id ON cedar_policies(resource_id);

--------------------------------------------------------------------------------
-- profile_metadata
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profile_metadata (
    profile_id  BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (profile_id, key)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_profile_metadata_profile_id ON profile_metadata(profile_id);

--------------------------------------------------------------------------------
-- profile_grants
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profile_grants (
    id          BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id  BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    profile_id  BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    role_keys   TEXT NOT NULL DEFAULT '',
    granted_by  TEXT,
    expires_at  TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (project_id, profile_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_profile_grants_profile_id ON profile_grants(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_grants_project_id ON profile_grants(project_id);

--------------------------------------------------------------------------------
-- devices
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS devices (
    id                BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id        BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
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
) STRICT;

CREATE INDEX IF NOT EXISTS idx_devices_profile_id ON devices(profile_id);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(profile_id, fingerprint_hash);

--------------------------------------------------------------------------------
-- device_authorization_codes
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS device_authorization_codes (
    id                BLOB PRIMARY KEY CHECK (length(id) = 16),
    client_id         TEXT NOT NULL,
    device_code_hash  BLOB NOT NULL,
    user_code         TEXT NOT NULL,
    scope             TEXT,
    status            TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'authorized', 'denied', 'expired', 'redeemed')),
    authorized_by     BLOB CHECK (length(authorized_by) = 16) REFERENCES profiles(id) ON DELETE SET NULL,
    project_id        BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    interval_secs     INTEGER NOT NULL DEFAULT 5,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at        TEXT NOT NULL,
    authorized_at     TEXT,
    last_polled_at    TEXT,
    redeemed_session_id BLOB CHECK (length(redeemed_session_id) = 16) REFERENCES sessions(id) ON DELETE SET NULL,
    -- The resource the device requested a token for (RFC 8707).
    resource_id       BLOB NOT NULL CHECK (length(resource_id) = 16) REFERENCES protected_resources(id),
    -- The authentication of the session the user approved from, set with
    -- authorized_by: the device's tokens report it.
    authorizing_session_id BLOB CHECK (length(authorizing_session_id) = 16),
    authenticated_at  TEXT,
    amr               TEXT,
    assurance_level   TEXT CHECK (assurance_level IN ('basic', 'standard')),
    elevation_level   TEXT,
    elevation_until   TEXT,
    CHECK ((authorizing_session_id IS NULL AND authenticated_at IS NULL AND amr IS NULL
            AND assurance_level IS NULL AND elevation_level IS NULL)
        OR (authorizing_session_id IS NOT NULL AND authenticated_at IS NOT NULL
            AND amr IS NOT NULL AND assurance_level IS NOT NULL)),
    CHECK ((elevation_level IS NULL AND elevation_until IS NULL)
        OR (elevation_level IN ('elevated', 'critical') AND elevation_until IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_auth_device_code_hash ON device_authorization_codes(device_code_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_auth_user_code ON device_authorization_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_auth_expires_at ON device_authorization_codes(expires_at) WHERE status = 'pending';

--------------------------------------------------------------------------------
-- upstream_providers
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS upstream_providers (
    id                      BLOB PRIMARY KEY CHECK (length(id) = 16),
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
) STRICT;

CREATE INDEX IF NOT EXISTS idx_upstream_providers_enabled ON upstream_providers(enabled) WHERE enabled = 1;

--------------------------------------------------------------------------------
-- upstream_identities
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS upstream_identities (
    id                BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id        BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    provider_id       BLOB NOT NULL CHECK (length(provider_id) = 16) REFERENCES upstream_providers(id) ON DELETE CASCADE,
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
) STRICT;

CREATE INDEX IF NOT EXISTS idx_upstream_identities_profile ON upstream_identities(profile_id);

--------------------------------------------------------------------------------
-- personal_access_tokens
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id            BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id    BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
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
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_pat_token_hash ON personal_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_pat_profile_status ON personal_access_tokens(profile_id, status);

--------------------------------------------------------------------------------
-- machine_users
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS machine_users (
    id                  BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id          BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    machine_type        TEXT NOT NULL DEFAULT 'service'
                        CHECK (machine_type IN ('service', 'bot', 'agent')),
    owner_type          TEXT NOT NULL
                        CHECK (owner_type IN ('profile', 'organization', 'system')),
    owner_id            BLOB CHECK (length(owner_id) = 16)
                        CHECK ((owner_type = 'system') = (owner_id IS NULL)),
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
) STRICT;

CREATE INDEX IF NOT EXISTS idx_machine_users_project ON machine_users(project_id);
CREATE INDEX IF NOT EXISTS idx_machine_users_owner ON machine_users(owner_type, owner_id);

--------------------------------------------------------------------------------
-- machine_user_credentials
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS machine_user_credentials (
    kid             TEXT PRIMARY KEY,
    machine_user_id BLOB NOT NULL CHECK (length(machine_user_id) = 16) REFERENCES machine_users(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL
                    CHECK (credential_type IN ('client_secret', 'private_key_jwt', 'mtls', 'workload_identity')),
    credential_data TEXT NOT NULL,
    algorithm       TEXT,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'grace_period', 'expired', 'revoked')),
    expires_at      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_machine_creds_user ON machine_user_credentials(machine_user_id);

--------------------------------------------------------------------------------
-- impersonation_grants
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS impersonation_grants (
    machine_user_id BLOB NOT NULL CHECK (length(machine_user_id) = 16) REFERENCES machine_users(id) ON DELETE CASCADE,
    target_type     TEXT NOT NULL CHECK (target_type IN ('role', 'user')),
    target          TEXT NOT NULL,
    allowed_scopes  TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (machine_user_id, target_type, target)
) STRICT;

--------------------------------------------------------------------------------
-- principal_quarantine
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS principal_quarantine (
    principal_hash   TEXT PRIMARY KEY,
    principal_type   TEXT NOT NULL,
    quarantine_until TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_principal_quarantine_until ON principal_quarantine(quarantine_until);

--------------------------------------------------------------------------------
-- closure_requests
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS closure_requests (
    profile_id       BLOB PRIMARY KEY CHECK (length(profile_id) = 16) REFERENCES profiles(id),
    mode             TEXT NOT NULL
                     CHECK (mode IN ('voluntary', 'gdpr_erasure', 'admin_termination', 'regulatory_order')),
    closure_reason   TEXT,
    requested_by     BLOB NOT NULL CHECK (length(requested_by) = 16),
    requested_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    grace_period_end TEXT,
    export_status    TEXT NOT NULL DEFAULT 'not_started'
                     CHECK (export_status IN ('not_started', 'preparing', 'ready', 'downloaded', 'expired')),
    cancel_count     INTEGER NOT NULL DEFAULT 0,
    legal_hold       TEXT
) STRICT;

--------------------------------------------------------------------------------
-- export_jobs
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS export_jobs (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id      BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    format          TEXT NOT NULL CHECK (format IN ('json')),
    status          TEXT NOT NULL
                    CHECK (status IN ('not_started', 'preparing', 'ready', 'downloaded', 'expired')),
    archive_path    TEXT,
    size_bytes      INTEGER,
    checksum_sha256 TEXT,
    created_at      TEXT NOT NULL,
    ready_at        TEXT,
    expires_at      TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_export_jobs_profile ON export_jobs(profile_id);

--------------------------------------------------------------------------------
-- magic_link_sessions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS magic_link_sessions (
    id          BLOB PRIMARY KEY CHECK (length(id) = 16),
    email       TEXT NOT NULL,
    destination TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    sealed_token BLOB NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0,
    client_id   TEXT,
    redirect_uri TEXT,
    scopes      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at  TEXT NOT NULL
) STRICT;

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
    ip_address  BLOB CHECK (length(ip_address) IN (4, 16)),
    device_id   TEXT,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL,
    UNIQUE (chain_id, sequence)
) STRICT;

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
) STRICT;

-- Where a chain resumes after retention removed its oldest records.
CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
    chain_id    TEXT PRIMARY KEY,
    sequence    INTEGER NOT NULL CHECK (sequence > 0),
    hash        TEXT NOT NULL,
    cut_before  TEXT NOT NULL
) STRICT;

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
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id      BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'published', 'archived')),
    data            TEXT NOT NULL,
    revision        INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_branding_configs_project_status
    ON branding_configs(project_id, status);

-- Only one published config per project.
CREATE UNIQUE INDEX IF NOT EXISTS idx_branding_configs_published
    ON branding_configs(project_id) WHERE status = 'published';

--------------------------------------------------------------------------------
-- flow_configs, flow_actions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS flow_configs (
    project_id  BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    flow_type   TEXT NOT NULL,
    data        TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (project_id, flow_type)
) STRICT;

CREATE TABLE IF NOT EXISTS flow_actions (
    id            BLOB PRIMARY KEY CHECK (length(id) = 16),
    project_id    BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    flow_type     TEXT NOT NULL,
    action_point  TEXT NOT NULL,
    action_order  INTEGER NOT NULL DEFAULT 0,
    data          TEXT NOT NULL,
    revision      INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_flow_actions_project_flow
    ON flow_actions(project_id, flow_type, action_point, action_order);

--------------------------------------------------------------------------------
-- consents, claim_grants
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS consents (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id      BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL,
    status          TEXT NOT NULL
                        CHECK (status IN ('requested', 'active', 'revoked', 'expired')),
    consented_at    TEXT NOT NULL,
    revoked_at      TEXT,
    updated_at      TEXT NOT NULL,
    UNIQUE (profile_id, client_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_consents_client ON consents(client_id);

CREATE TABLE IF NOT EXISTS claim_grants (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    consent_id      BLOB NOT NULL CHECK (length(consent_id) = 16) REFERENCES consents(id) ON DELETE CASCADE,
    claim_name      TEXT NOT NULL,
    claim_type      TEXT NOT NULL CHECK (claim_type IN ('data', 'attestation')),
    granted_at      TEXT NOT NULL,
    revoked_at      TEXT,
    UNIQUE (consent_id, claim_name)
) STRICT;

--------------------------------------------------------------------------------
-- invites, registration_sources
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS invites (
    id                 BLOB PRIMARY KEY CHECK (length(id) = 16),
    code               TEXT NOT NULL,
    created_by         BLOB CHECK (length(created_by) = 16) REFERENCES profiles(id),
    created_by_machine BLOB CHECK (length(created_by_machine) = 16) REFERENCES machine_users(id),
    created_by_name    TEXT NOT NULL,
    metadata           TEXT NOT NULL,
    max_uses           INTEGER NOT NULL CHECK (max_uses >= 0),
    use_count          INTEGER NOT NULL CHECK (use_count >= 0),
    expires_at         TEXT,
    active             INTEGER NOT NULL,
    created_at         TEXT NOT NULL,
    CONSTRAINT invites_one_creator
        CHECK ((created_by IS NULL) <> (created_by_machine IS NULL))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_code ON invites (UPPER(code));
CREATE INDEX IF NOT EXISTS idx_invites_created_id ON invites (created_at DESC, id DESC);

-- The registrations that used an invite, and the credential each installed.
CREATE TABLE IF NOT EXISTS invite_redemptions (
    invite_id     BLOB NOT NULL CHECK (length(invite_id) = 16) REFERENCES invites(id) ON DELETE CASCADE,
    profile_id    BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    redeemed_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    credential_id BLOB CHECK (length(credential_id) = 16) REFERENCES credentials(id) ON DELETE SET NULL,
    PRIMARY KEY (invite_id, profile_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_invite_redemptions_order
    ON invite_redemptions (invite_id, redeemed_at, profile_id);

CREATE TABLE IF NOT EXISTS registration_sources (
    profile_id      BLOB PRIMARY KEY CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    source_type     TEXT NOT NULL CHECK (source_type IN (
                        'self_signup', 'invite', 'admin_created',
                        'scim_provisioned', 'federation', 'identity_brokered')),
    source_id       TEXT NOT NULL,
    referrer_id     BLOB CHECK (length(referrer_id) = 16) REFERENCES profiles(id),
    utm_source      TEXT NOT NULL,
    utm_medium      TEXT NOT NULL,
    utm_campaign    TEXT NOT NULL,
    utm_term        TEXT NOT NULL,
    utm_content     TEXT NOT NULL,
    client_id       TEXT,
    created_at      TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_registration_sources_type_date
    ON registration_sources (source_type, created_at DESC);

--------------------------------------------------------------------------------
-- access_requests, notification_preferences
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS access_requests (
    id                       BLOB PRIMARY KEY CHECK (length(id) = 16),
    requester_id             BLOB NOT NULL CHECK (length(requester_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    project_id               BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id) ON DELETE CASCADE,
    role_key                 TEXT NOT NULL,
    justification            TEXT,
    requested_duration_hours INTEGER CHECK (requested_duration_hours >= 0),
    status                   TEXT NOT NULL CHECK (status IN (
                                 'pending', 'approved', 'denied', 'cancelled', 'expired')),
    reviewed_by              BLOB CHECK (length(reviewed_by) = 16) REFERENCES profiles(id),
    review_comment           TEXT,
    created_at               TEXT NOT NULL,
    reviewed_at              TEXT,
    expires_at               TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);

CREATE TABLE IF NOT EXISTS device_attestations (
    id                      BLOB PRIMARY KEY CHECK (length(id) = 16),
    device_id               BLOB NOT NULL UNIQUE CHECK (length(device_id) = 16),
    profile_id              BLOB NOT NULL CHECK (length(profile_id) = 16),
    format                  TEXT NOT NULL,
    key_storage             TEXT NOT NULL,
    status                  TEXT NOT NULL,
    public_jwk              TEXT NOT NULL,
    attestation_object      BLOB,
    attestation_certificate BLOB,
    aaguid                  TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    revoked_at              TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_device_attestations_profile_id
    ON device_attestations (profile_id);

CREATE TABLE IF NOT EXISTS anomaly_events (
    id          BLOB PRIMARY KEY CHECK (length(id) = 16),
    rule_id     TEXT NOT NULL,
    profile_id  TEXT NOT NULL,
    ip_address  BLOB CHECK (length(ip_address) IN (4, 16)),
    description TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    reaction    TEXT NOT NULL,
    timestamp   TEXT NOT NULL
) STRICT;

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
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ip_reputation_score ON ip_reputation (score DESC);

CREATE TABLE IF NOT EXISTS ip_allowlist_entries (
    cidr        TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS profile_locations (
    profile_id  BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    country     TEXT NOT NULL,
    latitude    REAL NOT NULL,
    longitude   REAL NOT NULL,
    login_count INTEGER NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    designated  INTEGER NOT NULL,
    PRIMARY KEY (profile_id, country)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sessions_device_lookup
    ON sessions (profile_id, device_id, created_at DESC) WHERE device_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS password_reset_sessions (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    profile_id      BLOB NOT NULL CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    destination     TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    sealed_token    BLOB NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'completed', 'expired')),
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    verified_at     TEXT,
    completed_at    TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_password_reset_sessions_profile
    ON password_reset_sessions (profile_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scim_outbound_targets (
    id                BLOB PRIMARY KEY CHECK (length(id) = 16),
    client_id         TEXT NOT NULL,
    project_id        BLOB NOT NULL CHECK (length(project_id) = 16) REFERENCES projects(id),
    display_name      TEXT NOT NULL,
    endpoint_url      TEXT NOT NULL,
    auth_config       TEXT NOT NULL,
    attribute_mapping TEXT NOT NULL,
    group_push        TEXT NOT NULL,
    sync_config       TEXT NOT NULL,
    enabled           INTEGER NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_scim_outbound_targets_project
    ON scim_outbound_targets (project_id);

CREATE TABLE IF NOT EXISTS scim_outbound_records (
    target_id       BLOB NOT NULL CHECK (length(target_id) = 16) REFERENCES scim_outbound_targets(id) ON DELETE CASCADE,
    sid_entity_id   BLOB NOT NULL CHECK (length(sid_entity_id) = 16),
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('user', 'group')),
    downstream_id   TEXT NOT NULL,
    last_synced_at  TEXT NOT NULL,
    last_error      TEXT,
    failure_count   INTEGER NOT NULL CHECK (failure_count >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (target_id, sid_entity_id, entity_type)
) STRICT;

CREATE TABLE IF NOT EXISTS scim_outbound_dlq (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    target_id       BLOB NOT NULL CHECK (length(target_id) = 16) REFERENCES scim_outbound_targets(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    payload         TEXT NOT NULL,
    sid_entity_id   BLOB NOT NULL CHECK (length(sid_entity_id) = 16),
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('user', 'group')),
    error           TEXT NOT NULL,
    attempts        INTEGER NOT NULL CHECK (attempts >= 0),
    first_attempt   TEXT NOT NULL,
    last_attempt    TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_scim_outbound_dlq_target ON scim_outbound_dlq (target_id);

CREATE TABLE IF NOT EXISTS notification_preferences (
    profile_id      BLOB PRIMARY KEY CHECK (length(profile_id) = 16) REFERENCES profiles(id) ON DELETE CASCADE,
    preferences     TEXT NOT NULL,
    updated_at      TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS provisioning_connectors (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    org_id          BLOB NOT NULL CHECK (length(org_id) = 16),
    direction       TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    client_id       TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('active', 'disabled', 'retired')),
    revision        INTEGER NOT NULL CHECK (revision >= 1),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_provisioning_connectors_org
    ON provisioning_connectors (org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS provisioning_credentials (
    id              BLOB PRIMARY KEY CHECK (length(id) = 16),
    connector_id    BLOB NOT NULL CHECK (length(connector_id) = 16) REFERENCES provisioning_connectors(id),
    kind            TEXT NOT NULL CHECK (kind IN ('scim_bearer', 'client_secret')),
    status          TEXT NOT NULL CHECK (status IN ('active', 'grace_period', 'expired', 'revoked')),
    verifier        TEXT NOT NULL UNIQUE,
    expires_at      TEXT,
    created_at      TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_provisioning_credentials_connector
    ON provisioning_credentials (connector_id, created_at DESC);

CREATE TABLE IF NOT EXISTS login_policy_epoch (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    epoch           INTEGER NOT NULL
) STRICT;
"#;
