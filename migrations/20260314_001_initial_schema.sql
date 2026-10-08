-- StructuredID CE — Initial Schema (squashed)
--
-- Squashed from 18 migrations (001 through 017, including 013b) into a single
-- initial schema. All tables represent the final state with complete column
-- definitions.

--------------------------------------------------------------------------------
-- Enum types
--------------------------------------------------------------------------------

CREATE TYPE enrollment_mode AS ENUM (
    'open',
    'invite_only',
    'admin_only',
    'domain_restricted'
);

CREATE TYPE invite_status AS ENUM (
    'active',
    'consumed',
    'revoked',
    'expired'
);

CREATE TYPE registration_source_type AS ENUM (
    'self_signup',
    'invite',
    'admin_created',
    'scim_provisioned',
    'federation',
    'identity_brokered'
);

--------------------------------------------------------------------------------
-- Utility functions
--------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Audit append-only enforcement (defense-in-depth trigger function)
CREATE OR REPLACE FUNCTION audit_records_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_records is append-only: % operations are forbidden', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

--------------------------------------------------------------------------------
-- profiles
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profiles (
    id                      UUID PRIMARY KEY,
    username                VARCHAR(255) NOT NULL UNIQUE,
    email                   VARCHAR(255),
    email_verified          BOOLEAN NOT NULL DEFAULT FALSE,
    display_name            VARCHAR(255),
    profile_type            VARCHAR(20) NOT NULL DEFAULT 'personal',
    status                  VARCHAR(20) NOT NULL DEFAULT 'active',
    visibility              VARCHAR(20) NOT NULL DEFAULT 'public',
    roles                   TEXT NOT NULL DEFAULT '',
    max_assurance           VARCHAR(20) NOT NULL DEFAULT 'anonymous',
    manager_id              UUID REFERENCES profiles(id) ON DELETE SET NULL,
    migration_pending       BOOLEAN NOT NULL DEFAULT FALSE,
    migration_started_at    TIMESTAMPTZ,
    migration_completed_at  TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_email ON profiles(email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_profiles_username ON profiles(username);
CREATE INDEX IF NOT EXISTS idx_profiles_status ON profiles(status);
CREATE INDEX IF NOT EXISTS idx_profiles_created_at ON profiles(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_migration_pending
    ON profiles(migration_pending) WHERE migration_pending = TRUE;

DROP TRIGGER IF EXISTS update_profiles_updated_at ON profiles;
CREATE TRIGGER update_profiles_updated_at
    BEFORE UPDATE ON profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

--------------------------------------------------------------------------------
-- credentials
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS credentials (
    id                  UUID PRIMARY KEY,
    profile_id          UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    credential_type     VARCHAR(50) NOT NULL,
    data                BYTEA NOT NULL,
    label               VARCHAR(255),
    history_commitment  BYTEA,
    commitment_salt     BYTEA,
    policy_version      INTEGER,
    zkpp_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    opaque_curve        SMALLINT,
    legacy_algorithm    VARCHAR(50),
    status              VARCHAR(20) NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'revoked')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_credentials_profile_id ON credentials(profile_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_credentials_profile_type ON credentials(profile_id, credential_type);
CREATE INDEX IF NOT EXISTS idx_credentials_opaque_curve ON credentials(opaque_curve) WHERE opaque_curve IS NOT NULL;

--------------------------------------------------------------------------------
-- sessions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sessions (
    id                UUID PRIMARY KEY,
    profile_id        UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    client_id         VARCHAR(255),
    device_id         UUID,
    ip_address        VARCHAR(45) NOT NULL,
    user_agent        TEXT,
    scopes            TEXT NOT NULL DEFAULT '',
    assurance_level   VARCHAR(20) NOT NULL DEFAULT 'basic',
    is_provisional    BOOLEAN NOT NULL DEFAULT FALSE,
    passkey_prompt    BOOLEAN NOT NULL DEFAULT FALSE,
    authenticated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    amr               TEXT NOT NULL DEFAULT '',
    policy_grace      BOOLEAN NOT NULL DEFAULT FALSE,
    grace_deadline    TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    last_activity_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_profile_id ON sessions(profile_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_client_id ON sessions(client_id) WHERE client_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id) WHERE device_id IS NOT NULL;

--------------------------------------------------------------------------------
-- projects
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS projects (
    id          UUID PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner_id    UUID REFERENCES profiles(id) ON DELETE SET NULL,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id) WHERE owner_id IS NOT NULL;

DROP TRIGGER IF EXISTS update_projects_updated_at ON projects;
CREATE TRIGGER update_projects_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Default system project (CE instance IS the organization)
INSERT INTO projects (id, name, description, is_system)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'SID',
    'Default system project',
    TRUE
) ON CONFLICT (id) DO NOTHING;

--------------------------------------------------------------------------------
-- oauth2_clients
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oauth2_clients (
    client_id                           VARCHAR(255) PRIMARY KEY,
    client_secret_hash                  BYTEA,
    redirect_uris                       TEXT NOT NULL DEFAULT '',
    allowed_scopes                      TEXT NOT NULL DEFAULT 'openid profile email',
    grant_types                         TEXT NOT NULL DEFAULT 'authorization_code',
    client_name                         VARCHAR(255) NOT NULL,
    active                              BOOLEAN NOT NULL DEFAULT TRUE,
    project_id                          UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'
                                        REFERENCES projects(id),
    application_type                    VARCHAR(32) NOT NULL DEFAULT 'web',
    required_acr                        VARCHAR(20),
    required_amr                        TEXT NOT NULL DEFAULT '',
    enforcement_mode                    VARCHAR(20) NOT NULL DEFAULT 'audit',
    min_device_assurance                VARCHAR(20),
    require_verified_email              BOOLEAN,
    require_verified_phone              BOOLEAN,
    backchannel_logout_uri              TEXT,
    backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    claim_mappings                      TEXT,
    created_at                          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_project ON oauth2_clients(project_id);

--------------------------------------------------------------------------------
-- refresh_tokens
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY,
    token_hash  BYTEA NOT NULL UNIQUE,
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    client_id   VARCHAR(255) NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    replaced_by UUID
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_profile ON refresh_tokens(profile_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);

--------------------------------------------------------------------------------
-- authorization_codes
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash       BYTEA PRIMARY KEY,
    profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    client_id       VARCHAR(255) NOT NULL,
    redirect_uri    TEXT NOT NULL,
    scopes          TEXT NOT NULL DEFAULT '',
    code_challenge  VARCHAR(128),
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used            BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);

--------------------------------------------------------------------------------
-- roles
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    permissions TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_roles_project_id ON roles(project_id);

--------------------------------------------------------------------------------
-- groups
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS groups (
    id              UUID PRIMARY KEY,
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    parent_group_id UUID REFERENCES groups(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_groups_project_id ON groups(project_id);
CREATE INDEX IF NOT EXISTS idx_groups_parent ON groups(parent_group_id) WHERE parent_group_id IS NOT NULL;

--------------------------------------------------------------------------------
-- group_members
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS group_members (
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_profile_id ON group_members(profile_id);

--------------------------------------------------------------------------------
-- role_assignments
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS role_assignments (
    id              UUID PRIMARY KEY,
    profile_id      UUID REFERENCES profiles(id) ON DELETE CASCADE,
    group_id        UUID REFERENCES groups(id) ON DELETE CASCADE,
    machine_user_id UUID,
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope           TEXT,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_principal CHECK (
        (profile_id IS NOT NULL AND group_id IS NULL AND machine_user_id IS NULL) OR
        (profile_id IS NULL AND group_id IS NOT NULL AND machine_user_id IS NULL) OR
        (profile_id IS NULL AND group_id IS NULL AND machine_user_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_profile_id ON role_assignments(profile_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_group_id ON role_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_role_id ON role_assignments(role_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_machine_user_id ON role_assignments(machine_user_id);

--------------------------------------------------------------------------------
-- cedar_policies
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cedar_policies (
    id          UUID PRIMARY KEY,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    policy_text TEXT NOT NULL,
    effect      TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_cedar_policies_project_id ON cedar_policies(project_id);

--------------------------------------------------------------------------------
-- entity_attributes
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS entity_attributes (
    entity_id   TEXT NOT NULL,
    attr_key    TEXT NOT NULL,
    attr_value  JSONB NOT NULL,
    PRIMARY KEY (entity_id, attr_key)
);

CREATE INDEX IF NOT EXISTS idx_entity_attributes_entity_id ON entity_attributes(entity_id);

--------------------------------------------------------------------------------
-- identifiers
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identifiers (
    id              UUID PRIMARY KEY,
    profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    identifier_type VARCHAR(30) NOT NULL,
    value           TEXT NOT NULL,
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    is_primary      BOOLEAN NOT NULL DEFAULT FALSE,
    login_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_identifiers_type_value
    ON identifiers(identifier_type, value);
CREATE INDEX IF NOT EXISTS idx_identifiers_profile_id
    ON identifiers(profile_id);
CREATE INDEX IF NOT EXISTS idx_identifiers_value
    ON identifiers(value);

--------------------------------------------------------------------------------
-- profile_metadata
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profile_metadata (
    profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (profile_id, key)
);

CREATE INDEX IF NOT EXISTS idx_profile_metadata_profile_id ON profile_metadata(profile_id);

--------------------------------------------------------------------------------
-- profile_grants
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS profile_grants (
    id          UUID PRIMARY KEY,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    role_keys   TEXT NOT NULL DEFAULT '',
    granted_by  TEXT,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_profile_grants_profile_id ON profile_grants(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_grants_project_id ON profile_grants(project_id);

--------------------------------------------------------------------------------
-- device_authorization_codes
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS device_authorization_codes (
    id                UUID PRIMARY KEY,
    client_id         VARCHAR(255) NOT NULL,
    device_code_hash  BYTEA NOT NULL,
    user_code         VARCHAR(16) NOT NULL,
    scope             TEXT,
    status            VARCHAR(32) NOT NULL DEFAULT 'pending',
    authorized_by     UUID REFERENCES profiles(id) ON DELETE SET NULL,
    project_id        UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    interval_secs     INTEGER NOT NULL DEFAULT 5,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    authorized_at     TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_auth_device_code_hash
    ON device_authorization_codes(device_code_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_auth_user_code
    ON device_authorization_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_auth_expires_at
    ON device_authorization_codes(expires_at)
    WHERE status = 'pending';

--------------------------------------------------------------------------------
-- upstream_providers
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS upstream_providers (
    id                      UUID PRIMARY KEY,
    name                    VARCHAR(255) NOT NULL UNIQUE,
    protocol                VARCHAR(20) NOT NULL CHECK (protocol IN ('oidc', 'oauth2')),
    trust_category          VARCHAR(20) NOT NULL DEFAULT 'social'
                            CHECK (trust_category IN ('social', 'corporate', 'government', 'financial')),
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    client_id               VARCHAR(255) NOT NULL,
    client_secret           BYTEA NOT NULL,
    discovery_url           TEXT,
    authorization_endpoint  TEXT,
    token_endpoint          TEXT,
    userinfo_endpoint       TEXT,
    scopes                  JSONB NOT NULL DEFAULT '["openid","profile","email"]',
    show_on_login           BOOLEAN NOT NULL DEFAULT true,
    display_order           INTEGER NOT NULL DEFAULT 0,
    logo_url                TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_upstream_providers_enabled
    ON upstream_providers(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_upstream_providers_display
    ON upstream_providers(display_order) WHERE show_on_login = true;

--------------------------------------------------------------------------------
-- upstream_identities
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS upstream_identities (
    id                UUID PRIMARY KEY,
    profile_id        UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    provider_id       UUID NOT NULL REFERENCES upstream_providers(id) ON DELETE CASCADE,
    upstream_subject  VARCHAR(255) NOT NULL,
    upstream_issuer   VARCHAR(255),
    upstream_email    VARCHAR(255),
    upstream_name     VARCHAR(255),
    upstream_picture  TEXT,
    linked_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at     TIMESTAMPTZ,
    login_count       BIGINT NOT NULL DEFAULT 0,
    UNIQUE(profile_id, provider_id),
    UNIQUE(provider_id, upstream_subject)
);

CREATE INDEX IF NOT EXISTS idx_upstream_identities_profile
    ON upstream_identities(profile_id);
CREATE INDEX IF NOT EXISTS idx_upstream_identities_email
    ON upstream_identities(upstream_email) WHERE upstream_email IS NOT NULL;

--------------------------------------------------------------------------------
-- personal_access_tokens
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id            UUID PRIMARY KEY,
    profile_id    UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    name          VARCHAR(255) NOT NULL,
    description   TEXT,
    token_hash    VARCHAR(64) NOT NULL,
    token_prefix  VARCHAR(20) NOT NULL,
    scopes        TEXT NOT NULL DEFAULT '',
    ip_allowlist  TEXT NOT NULL DEFAULT '',
    status        VARCHAR(20) NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'revoked', 'expired')),
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    last_used_ip  VARCHAR(45),
    use_count     BIGINT NOT NULL DEFAULT 0,
    revoked_at    TIMESTAMPTZ,
    revoked_by    VARCHAR(255),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pat_token_hash
    ON personal_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_pat_profile_status
    ON personal_access_tokens(profile_id, status);

--------------------------------------------------------------------------------
-- machine_users
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS machine_users (
    id                  UUID PRIMARY KEY,
    project_id          UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    machine_type        VARCHAR(20) NOT NULL DEFAULT 'service'
                        CHECK (machine_type IN ('service', 'bot', 'agent')),
    owner_type          VARCHAR(20) NOT NULL DEFAULT 'profile'
                        CHECK (owner_type IN ('profile', 'organization', 'system')),
    owner_id            VARCHAR(255) NOT NULL,
    client_id           VARCHAR(255) NOT NULL UNIQUE,
    display_name        VARCHAR(255) NOT NULL,
    description         TEXT,
    status              VARCHAR(20) NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'suspended', 'expired', 'deleted')),
    scopes              TEXT NOT NULL DEFAULT '',
    roles               TEXT NOT NULL DEFAULT '',
    ip_allowlist        TEXT NOT NULL DEFAULT '',
    rate_limit_rpm      INTEGER NOT NULL DEFAULT 0,
    max_token_lifetime  INTEGER,
    last_used_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_machine_users_project
    ON machine_users(project_id);
CREATE INDEX IF NOT EXISTS idx_machine_users_owner
    ON machine_users(owner_type, owner_id);

--------------------------------------------------------------------------------
-- machine_user_credentials
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS machine_user_credentials (
    kid             VARCHAR(255) PRIMARY KEY,
    machine_user_id UUID NOT NULL REFERENCES machine_users(id) ON DELETE CASCADE,
    credential_type VARCHAR(30) NOT NULL
                    CHECK (credential_type IN ('client_secret', 'private_key_jwt', 'mtls', 'workload_identity')),
    credential_data TEXT NOT NULL,
    algorithm       VARCHAR(20),
    status          VARCHAR(20) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'grace_period', 'expired', 'revoked')),
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_machine_creds_user
    ON machine_user_credentials(machine_user_id);

--------------------------------------------------------------------------------
-- impersonation_grants
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS impersonation_grants (
    id              UUID PRIMARY KEY,
    machine_user_id UUID NOT NULL REFERENCES machine_users(id) ON DELETE CASCADE,
    target_type     VARCHAR(20) NOT NULL CHECK (target_type IN ('role', 'user')),
    target          VARCHAR(255) NOT NULL,
    allowed_scopes  TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(machine_user_id, target_type, target)
);

CREATE INDEX IF NOT EXISTS idx_impersonation_machine
    ON impersonation_grants(machine_user_id);

--------------------------------------------------------------------------------
-- identifier_quarantine
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identifier_quarantine (
    identifier_hash VARCHAR(128) PRIMARY KEY,
    identifier_type VARCHAR(20) NOT NULL,
    quarantine_until TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_quarantine_until
    ON identifier_quarantine(quarantine_until);

--------------------------------------------------------------------------------
-- closure_requests
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS closure_requests (
    profile_id       UUID PRIMARY KEY REFERENCES profiles(id),
    mode             VARCHAR(30) NOT NULL
                     CHECK (mode IN ('voluntary', 'gdpr_erasure', 'admin_termination', 'regulatory_order')),
    closure_reason   TEXT,
    requested_by     UUID NOT NULL,
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    grace_period_end TIMESTAMPTZ,
    export_status    VARCHAR(20) NOT NULL DEFAULT 'not_started'
                     CHECK (export_status IN ('not_started', 'preparing', 'ready', 'downloaded', 'expired')),
    cancel_count     INTEGER NOT NULL DEFAULT 0
);

--------------------------------------------------------------------------------
-- audit_records
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_records (
    id          TEXT        PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    chain_id    TEXT        NOT NULL,
    sequence    BIGINT      NOT NULL,
    actor_id    TEXT        NOT NULL,
    actor_type  TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    resource    TEXT        NOT NULL,
    outcome     TEXT        NOT NULL,
    metadata    JSONB       NOT NULL DEFAULT '{}',
    ip_address  TEXT,
    device_id   TEXT,
    prev_hash   TEXT        NOT NULL,
    hash        TEXT        NOT NULL,

    CONSTRAINT uq_chain_sequence UNIQUE (chain_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_id ON audit_records (chain_id, sequence);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_records (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_records (action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_records (actor_id);

-- Enforce append-only on audit_records
DO $$
BEGIN
    REVOKE UPDATE, DELETE ON audit_records FROM PUBLIC;
    REVOKE TRUNCATE ON audit_records FROM PUBLIC;
END
$$;

DROP TRIGGER IF EXISTS trg_audit_records_no_update ON audit_records;
CREATE TRIGGER trg_audit_records_no_update
    BEFORE UPDATE ON audit_records
    FOR EACH ROW EXECUTE FUNCTION audit_records_immutable();

DROP TRIGGER IF EXISTS trg_audit_records_no_delete ON audit_records;
CREATE TRIGGER trg_audit_records_no_delete
    BEFORE DELETE ON audit_records
    FOR EACH ROW EXECUTE FUNCTION audit_records_immutable();

--------------------------------------------------------------------------------
-- audit_chain_heads
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_chain_heads (
    chain_id        TEXT    PRIMARY KEY,
    last_record_id  TEXT    NOT NULL,
    last_hash       TEXT    NOT NULL,
    sequence        BIGINT  NOT NULL
);

--------------------------------------------------------------------------------
-- scim_outbound_targets
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scim_outbound_targets (
    id              UUID PRIMARY KEY,
    client_id       TEXT NOT NULL,
    project_id      UUID NOT NULL REFERENCES projects(id),
    display_name    TEXT NOT NULL,
    endpoint_url    TEXT NOT NULL,
    auth_config     JSONB NOT NULL,
    attribute_mapping JSONB NOT NULL DEFAULT '{"mappings": []}',
    group_push      JSONB NOT NULL DEFAULT '{"enabled": false, "mapping": []}',
    sync_config     JSONB NOT NULL DEFAULT '{"max_retry_attempts": 5, "retry_backoff_base_secs": 1}',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scim_outbound_targets_project
    ON scim_outbound_targets(project_id);

--------------------------------------------------------------------------------
-- scim_outbound_records
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scim_outbound_records (
    target_id       UUID NOT NULL REFERENCES scim_outbound_targets(id) ON DELETE CASCADE,
    sid_entity_id   UUID NOT NULL,
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('user', 'group')),
    downstream_id   TEXT NOT NULL,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error      TEXT,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (target_id, sid_entity_id, entity_type)
);

CREATE INDEX IF NOT EXISTS idx_scim_outbound_records_downstream
    ON scim_outbound_records(target_id, downstream_id);

--------------------------------------------------------------------------------
-- scim_outbound_dlq
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scim_outbound_dlq (
    id              UUID PRIMARY KEY,
    target_id       UUID NOT NULL REFERENCES scim_outbound_targets(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    sid_entity_id   UUID NOT NULL,
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('user', 'group')),
    error           TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 1,
    first_attempt   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempt    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scim_outbound_dlq_target
    ON scim_outbound_dlq(target_id);

--------------------------------------------------------------------------------
-- branding_configs
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS branding_configs (
    id          UUID PRIMARY KEY,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'draft'
                CHECK (status IN ('draft', 'published', 'archived')),
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only one published config per project.
CREATE UNIQUE INDEX IF NOT EXISTS idx_branding_configs_published
    ON branding_configs (project_id) WHERE status = 'published';

CREATE INDEX IF NOT EXISTS idx_branding_configs_project_id
    ON branding_configs (project_id);

--------------------------------------------------------------------------------
-- flow_configs
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS flow_configs (
    project_id  UUID NOT NULL,
    flow_type   TEXT NOT NULL,
    data        JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, flow_type)
);

--------------------------------------------------------------------------------
-- flow_actions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS flow_actions (
    id            UUID PRIMARY KEY,
    project_id    UUID NOT NULL,
    flow_type     TEXT NOT NULL,
    action_point  TEXT NOT NULL,
    data          JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flow_actions_project_flow
    ON flow_actions (project_id, flow_type, action_point);

--------------------------------------------------------------------------------
-- security_policies
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS security_policies (
    id                                  UUID PRIMARY KEY,
    name                                TEXT NOT NULL DEFAULT 'Default',
    policy_json                         JSONB NOT NULL DEFAULT '{}',
    enrollment_mode                     enrollment_mode NOT NULL DEFAULT 'open',
    enrollment_invite_default_max_uses  INTEGER NOT NULL DEFAULT 1,
    enrollment_invite_default_expiry_hours INTEGER NOT NULL DEFAULT 72,
    enrollment_allowed_domains          TEXT[] NOT NULL DEFAULT '{}',
    enrollment_track_source             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_policies_enrollment_mode
    ON security_policies (enrollment_mode);

--------------------------------------------------------------------------------
-- invites
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS invites (
    id              UUID PRIMARY KEY,
    code            VARCHAR(8) NOT NULL,
    created_by      UUID NOT NULL REFERENCES profiles(id),
    created_by_name TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    max_uses        INTEGER NOT NULL DEFAULT 1,
    use_count       INTEGER NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_code ON invites (UPPER(code));
CREATE INDEX IF NOT EXISTS idx_invites_active ON invites (active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites (created_by);

--------------------------------------------------------------------------------
-- registration_sources
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS registration_sources (
    profile_id   UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    source_type  registration_source_type NOT NULL,
    source_id    TEXT NOT NULL,
    referrer_id  UUID REFERENCES profiles(id),
    utm_source   TEXT NOT NULL DEFAULT '',
    utm_medium   TEXT NOT NULL DEFAULT '',
    utm_campaign TEXT NOT NULL DEFAULT '',
    utm_term     TEXT NOT NULL DEFAULT '',
    utm_content  TEXT NOT NULL DEFAULT '',
    client_id    TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_registration_sources_type_date
    ON registration_sources (source_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_registration_sources_referrer
    ON registration_sources (referrer_id)
    WHERE referrer_id IS NOT NULL;

--------------------------------------------------------------------------------
-- magic_link_sessions
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS magic_link_sessions (
    id          UUID PRIMARY KEY,
    email       TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    consumed    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_magic_link_sessions_email ON magic_link_sessions(email);
CREATE INDEX IF NOT EXISTS idx_magic_link_sessions_expires ON magic_link_sessions(expires_at);

--------------------------------------------------------------------------------
-- profiles_view (read-only, schema isolation)
--------------------------------------------------------------------------------

CREATE OR REPLACE VIEW profiles_view AS
SELECT
    id,
    username,
    display_name,
    email,
    email_verified,
    status AS profile_status,
    created_at,
    updated_at
FROM profiles;

CREATE OR REPLACE RULE profiles_view_no_insert AS
    ON INSERT TO profiles_view DO INSTEAD NOTHING;
CREATE OR REPLACE RULE profiles_view_no_update AS
    ON UPDATE TO profiles_view DO INSTEAD NOTHING;
CREATE OR REPLACE RULE profiles_view_no_delete AS
    ON DELETE TO profiles_view DO INSTEAD NOTHING;
