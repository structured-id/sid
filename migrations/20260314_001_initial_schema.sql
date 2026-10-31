-- SPDX-License-Identifier: AGPL-3.0-only
-- The PostgreSQL schema of the engine. Before the first release a change edits
-- this file and the database is recreated. Tables are not schema-qualified: the
-- migrator's search_path places them.

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

CREATE FUNCTION audit_records_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'audit_records is append-only: % operations are forbidden', TG_OP;
    RETURN NULL;
END;
$$;

CREATE FUNCTION cleanup_expired_sessions() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;

CREATE FUNCTION create_audit_partition(year integer, month integer) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    partition_name := format('audit_records_%s_%s',
        year, lpad(month::TEXT, 2, '0'));
    start_date := make_date(year, month, 1);
    end_date := start_date + INTERVAL '1 month';

    PERFORM pg_advisory_xact_lock(
        hashtextextended(current_schema() || '.' || partition_name, 0));

    IF to_regclass(format('%I.%I', current_schema(), partition_name)) IS NOT NULL THEN
        RETURN partition_name || ' (already exists)';
    END IF;

    EXECUTE format(
        'CREATE TABLE %I.%I PARTITION OF %I.audit_records
         FOR VALUES FROM (%L) TO (%L)',
        current_schema(), partition_name, current_schema(), start_date, end_date
    );

    RETURN partition_name || ' (created)';
END;
$$;

CREATE FUNCTION principals_email_policy_fence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (NEW.principal_type = 'email') <> (NEW.email_policy_revision IS NOT NULL)
       OR (NEW.principal_type = 'email'
           AND (TG_OP = 'INSERT'
                OR NEW.value IS DISTINCT FROM OLD.value
                OR NEW.email_policy_revision IS DISTINCT FROM OLD.email_policy_revision)
           AND NEW.email_policy_revision IS DISTINCT FROM
               (SELECT revision FROM email_policy_activations WHERE scope = 'installation'))
    THEN
        RAISE EXCEPTION 'email key written under policy revision %, not the active one',
            NEW.email_policy_revision
            USING ERRCODE = 'SIDEP';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION refuse_admin_claim_when_centrally_managed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.name = 'admin_claim' AND EXISTS (SELECT 1 FROM bootstrap_policy) THEN
        RAISE EXCEPTION 'centrally managed installation: no administrator claim';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TABLE anomaly_events (
    id uuid NOT NULL,
    rule_id text NOT NULL,
    profile_id text DEFAULT ''::text NOT NULL,
    ip_address inet,
    description text DEFAULT ''::text NOT NULL,
    risk_score integer DEFAULT 0 NOT NULL,
    reaction text DEFAULT ''::text NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT anomaly_events_host_address CHECK ((masklen(ip_address) = CASE family(ip_address) WHEN 4 THEN 32 ELSE 128 END)),
    CONSTRAINT anomaly_events_pkey PRIMARY KEY (id)
);

CREATE TABLE audit_chain_checkpoints (
    chain_id text NOT NULL,
    sequence bigint NOT NULL,
    hash text NOT NULL,
    cut_before timestamp with time zone NOT NULL,
    CONSTRAINT audit_chain_checkpoints_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT audit_chain_checkpoints_pkey PRIMARY KEY (chain_id)
);

CREATE TABLE audit_chain_heads (
    chain_id text NOT NULL,
    last_record_id text NOT NULL,
    last_hash text NOT NULL,
    sequence bigint NOT NULL,
    CONSTRAINT audit_chain_heads_pkey PRIMARY KEY (chain_id)
);

CREATE TABLE audit_records (
    id text CONSTRAINT audit_records_id_not_null1 NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() CONSTRAINT audit_records_timestamp_not_null1 NOT NULL,
    chain_id text CONSTRAINT audit_records_chain_id_not_null1 NOT NULL,
    sequence bigint CONSTRAINT audit_records_sequence_not_null1 NOT NULL,
    actor_id text CONSTRAINT audit_records_actor_id_not_null1 NOT NULL,
    actor_type text CONSTRAINT audit_records_actor_type_not_null1 NOT NULL,
    action text CONSTRAINT audit_records_action_not_null1 NOT NULL,
    resource text CONSTRAINT audit_records_resource_not_null1 NOT NULL,
    outcome text CONSTRAINT audit_records_outcome_not_null1 NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb CONSTRAINT audit_records_metadata_not_null1 NOT NULL,
    ip_address inet,
    device_id text,
    prev_hash text CONSTRAINT audit_records_prev_hash_not_null1 NOT NULL,
    hash text CONSTRAINT audit_records_hash_not_null1 NOT NULL,
    CONSTRAINT audit_records_host_address CHECK ((masklen(ip_address) = CASE family(ip_address) WHEN 4 THEN 32 ELSE 128 END)),
    CONSTRAINT uq_audit_chain_seq UNIQUE (chain_id, sequence, "timestamp"),
    CONSTRAINT audit_records_pkey1 PRIMARY KEY (id, "timestamp")
)
PARTITION BY RANGE ("timestamp");

CREATE TABLE audit_records_2026_01 PARTITION OF audit_records FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00');

CREATE TABLE audit_records_2026_02 PARTITION OF audit_records FOR VALUES FROM ('2026-02-01 00:00:00+00') TO ('2026-03-01 00:00:00+00');

CREATE TABLE audit_records_2026_03 PARTITION OF audit_records FOR VALUES FROM ('2026-03-01 00:00:00+00') TO ('2026-04-01 00:00:00+00');

CREATE TABLE audit_records_2026_04 PARTITION OF audit_records FOR VALUES FROM ('2026-04-01 00:00:00+00') TO ('2026-05-01 00:00:00+00');

CREATE TABLE audit_records_2026_05 PARTITION OF audit_records FOR VALUES FROM ('2026-05-01 00:00:00+00') TO ('2026-06-01 00:00:00+00');

CREATE TABLE audit_records_2026_06 PARTITION OF audit_records FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');

CREATE TABLE audit_records_2026_07 PARTITION OF audit_records FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');

CREATE TABLE audit_records_2026_08 PARTITION OF audit_records FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');

CREATE TABLE audit_records_2026_09 PARTITION OF audit_records FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');

CREATE TABLE audit_records_2026_10 PARTITION OF audit_records FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');

CREATE TABLE audit_records_2026_11 PARTITION OF audit_records FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');

CREATE TABLE audit_records_2026_12 PARTITION OF audit_records FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');

CREATE TABLE audit_records_default PARTITION OF audit_records DEFAULT;

CREATE TABLE bootstrap_policy (
    scope text NOT NULL,
    policy text NOT NULL,
    adopted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT bootstrap_policy_policy_check CHECK ((policy = 'centrally_managed'::text)),
    CONSTRAINT bootstrap_policy_scope_check CHECK ((scope = 'installation'::text)),
    CONSTRAINT bootstrap_policy_pkey PRIMARY KEY (scope)
);

CREATE TABLE device_attestations (
    id uuid NOT NULL,
    device_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    format text DEFAULT 'none'::text NOT NULL,
    key_storage text DEFAULT 'software'::text NOT NULL,
    status text DEFAULT 'unverified'::text NOT NULL,
    device_public_key bytea NOT NULL,
    attestation_object bytea,
    attestation_certificate bytea,
    aaguid text,
    credential_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT device_attestations_device_id_key UNIQUE (device_id),
    CONSTRAINT device_attestations_pkey PRIMARY KEY (id)
);

CREATE TABLE devices (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    display_name text,
    device_type text DEFAULT 'desktop'::text NOT NULL,
    os_info text,
    assurance text DEFAULT 'unknown'::text NOT NULL,
    trusted boolean DEFAULT false NOT NULL,
    hardware_attested boolean DEFAULT false NOT NULL,
    fingerprint_hash text,
    last_ip_geo text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT devices_pkey PRIMARY KEY (id)
);

CREATE TABLE durable_work (
    id uuid NOT NULL,
    kind text NOT NULL,
    payload bytea NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer NOT NULL,
    generation bigint DEFAULT 0 NOT NULL,
    lease_owner text,
    lease_until timestamp with time zone,
    last_error text,
    ambiguous boolean DEFAULT false NOT NULL,
    result text,
    not_before timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT durable_work_max_attempts_check CHECK ((max_attempts > 0)),
    CONSTRAINT durable_work_pkey PRIMARY KEY (id)
);

CREATE TABLE email_policy_activations (
    scope text NOT NULL,
    revision bigint NOT NULL,
    activated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT email_policy_activations_revision_check CHECK ((revision > 0)),
    CONSTRAINT email_policy_activations_pkey PRIMARY KEY (scope)
);

CREATE TABLE email_provider_config (
    id uuid NOT NULL,
    smtp_host text DEFAULT ''::text NOT NULL,
    smtp_port integer DEFAULT 587 NOT NULL,
    from_address text DEFAULT ''::text NOT NULL,
    from_display_name text DEFAULT ''::text NOT NULL,
    reply_to text DEFAULT ''::text NOT NULL,
    encryption text DEFAULT 'starttls'::text NOT NULL,
    auth_type text DEFAULT 'none'::text NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    password_enc text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    oauth2_provider text,
    oauth2_tenant_id text,
    oauth2_client_id text,
    oauth2_client_secret text,
    oauth2_service_account_key text,
    oauth2_token_endpoint text,
    CONSTRAINT email_provider_config_pkey PRIMARY KEY (id)
);

CREATE TABLE enrollment_policy (
    scope text NOT NULL,
    mode text NOT NULL,
    allowed_domains text[] DEFAULT '{}'::text[] NOT NULL,
    track_source boolean NOT NULL,
    invite_default_max_uses bigint NOT NULL,
    invite_default_expiry_hours bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT enrollment_policy_domains_for_restricted_mode CHECK (((mode <> 'domain_restricted'::text) OR (cardinality(allowed_domains) > 0))),
    CONSTRAINT enrollment_policy_invite_default_expiry_hours_check CHECK (((invite_default_expiry_hours >= 0) AND (invite_default_expiry_hours <= '4294967295'::bigint))),
    CONSTRAINT enrollment_policy_invite_default_max_uses_check CHECK (((invite_default_max_uses >= 0) AND (invite_default_max_uses <= '4294967295'::bigint))),
    CONSTRAINT enrollment_policy_mode_check CHECK ((mode = ANY (ARRAY['open'::text, 'invite_only'::text, 'admin_only'::text, 'domain_restricted'::text]))),
    CONSTRAINT enrollment_policy_scope_check CHECK ((scope = 'installation'::text)),
    CONSTRAINT enrollment_policy_pkey PRIMARY KEY (scope)
);

CREATE TABLE entity_attributes (
    entity_id text NOT NULL,
    attr_key text NOT NULL,
    attr_value jsonb NOT NULL,
    CONSTRAINT entity_attributes_pkey PRIMARY KEY (entity_id, attr_key)
);

CREATE TABLE flow_actions (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    flow_type text NOT NULL,
    action_point text NOT NULL,
    data jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    action_order integer DEFAULT 0 NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT flow_actions_revision_check CHECK ((revision >= 0)),
    CONSTRAINT flow_actions_pkey PRIMARY KEY (id)
);

CREATE TABLE flow_configs (
    project_id uuid NOT NULL,
    flow_type text NOT NULL,
    data jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT flow_configs_pkey PRIMARY KEY (project_id, flow_type)
);

CREATE TABLE instance_secrets (
    name text NOT NULL,
    sealed bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT instance_secrets_pkey PRIMARY KEY (name)
);

CREATE TABLE ip_allowlist_entries (
    cidr text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ip_allowlist_entries_pkey PRIMARY KEY (cidr)
);

CREATE TABLE ip_reputation (
    ip text NOT NULL,
    failed_count integer DEFAULT 0 NOT NULL,
    success_count integer DEFAULT 0 NOT NULL,
    score real DEFAULT 0.0 NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_failed_at timestamp with time zone,
    last_success_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ip_reputation_pkey PRIMARY KEY (ip)
);

CREATE TABLE key_versions (
    version integer NOT NULL,
    salt bytea NOT NULL,
    algorithm text NOT NULL,
    context text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT key_versions_version_check CHECK ((version > 0)),
    CONSTRAINT key_versions_pkey PRIMARY KEY (version)
);

CREATE TABLE login_policy_epoch (
    id smallint NOT NULL,
    epoch bigint NOT NULL,
    CONSTRAINT login_policy_epoch_id_check CHECK ((id = 1)),
    CONSTRAINT login_policy_epoch_pkey PRIMARY KEY (id)
);

CREATE TABLE magic_link_sessions (
    id uuid NOT NULL,
    email text NOT NULL,
    token_hash text NOT NULL,
    consumed boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT magic_link_sessions_pkey PRIMARY KEY (id)
);

CREATE TABLE operation_results (
    namespace text NOT NULL,
    op_key text NOT NULL,
    method text NOT NULL,
    fingerprint bytea NOT NULL,
    result bytea NOT NULL,
    completed_at timestamp with time zone DEFAULT now() NOT NULL,
    retain_until timestamp with time zone,
    CONSTRAINT operation_results_pkey PRIMARY KEY (namespace, op_key)
);

CREATE TABLE organizations (
    id uuid NOT NULL,
    org_type text NOT NULL,
    status text NOT NULL,
    canonical_domain text NOT NULL,
    is_instance boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organizations_org_type_check CHECK ((org_type = ANY (ARRAY['family'::text, 'community'::text, 'commercial'::text, 'government'::text]))),
    CONSTRAINT organizations_status_check CHECK ((status = ANY (ARRAY['pending_dns'::text, 'pending_claim'::text, 'active_trial'::text, 'active'::text, 'suspended'::text, 'deprovisioning'::text, 'deleted'::text]))),
    CONSTRAINT organizations_pkey PRIMARY KEY (id)
);

CREATE TABLE password_history_write_cutoff (
    singleton boolean DEFAULT true NOT NULL,
    not_before timestamp with time zone,
    CONSTRAINT password_history_write_cutoff_singleton_check CHECK (singleton),
    CONSTRAINT password_history_write_cutoff_pkey PRIMARY KEY (singleton)
);

CREATE TABLE principal_quarantine (
    principal_hash character varying(128) CONSTRAINT identifier_quarantine_identifier_hash_not_null NOT NULL,
    principal_type character varying(20) CONSTRAINT identifier_quarantine_identifier_type_not_null NOT NULL,
    quarantine_until timestamp with time zone CONSTRAINT identifier_quarantine_quarantine_until_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT identifier_quarantine_created_at_not_null NOT NULL,
    CONSTRAINT identifier_quarantine_pkey PRIMARY KEY (principal_hash)
);

CREATE TABLE principals (
    id uuid CONSTRAINT identifiers_id_not_null NOT NULL,
    principal_type character varying(30) CONSTRAINT identifiers_identifier_type_not_null NOT NULL,
    value text CONSTRAINT identifiers_value_not_null NOT NULL,
    verified boolean DEFAULT false CONSTRAINT identifiers_verified_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT identifiers_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT identifiers_updated_at_not_null NOT NULL,
    verified_at timestamp with time zone,
    verification_expires timestamp with time zone,
    assigned_profile_id uuid,
    assignment_revision bigint DEFAULT 0 NOT NULL,
    email_policy_revision bigint,
    CONSTRAINT principals_email_policy_revision CHECK ((((principal_type)::text = 'email'::text) = (email_policy_revision IS NOT NULL))),
    CONSTRAINT identifiers_pkey PRIMARY KEY (id)
);

CREATE TABLE profiles (
    id uuid NOT NULL,
    username character varying(255),
    given_name character varying(255),
    profile_type character varying(20) DEFAULT 'personal'::character varying NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    visibility character varying(20) DEFAULT 'public'::character varying NOT NULL,
    roles text DEFAULT ''::text NOT NULL,
    max_assurance character varying(20) DEFAULT 'anonymous'::character varying NOT NULL,
    manager_id uuid,
    migration_pending boolean DEFAULT false NOT NULL,
    migration_started_at timestamp with time zone,
    migration_completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    family_name character varying(255),
    middle_name character varying(255),
    honorific_prefix character varying(100),
    honorific_suffix character varying(100),
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT profiles_revision_check CHECK ((revision >= 0)),
    CONSTRAINT profiles_pkey PRIMARY KEY (id),
    CONSTRAINT profiles_username_key UNIQUE (username),
    CONSTRAINT profiles_manager_id_fkey FOREIGN KEY (manager_id) REFERENCES profiles(id) ON DELETE SET NULL
);

CREATE TABLE provisioning_connectors (
    id uuid NOT NULL,
    org_id uuid NOT NULL,
    direction text NOT NULL,
    display_name text NOT NULL,
    state text NOT NULL,
    revision bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    client_id text NOT NULL,
    CONSTRAINT provisioning_connectors_direction_check CHECK ((direction = ANY (ARRAY['inbound'::text, 'outbound'::text]))),
    CONSTRAINT provisioning_connectors_revision_check CHECK ((revision >= 1)),
    CONSTRAINT provisioning_connectors_state_check CHECK ((state = ANY (ARRAY['active'::text, 'disabled'::text, 'retired'::text]))),
    CONSTRAINT provisioning_connectors_pkey PRIMARY KEY (id)
);

CREATE TABLE security_policies (
    id uuid NOT NULL,
    name text DEFAULT 'Default'::text NOT NULL,
    policy_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    enrollment_mode enrollment_mode DEFAULT 'open'::enrollment_mode NOT NULL,
    enrollment_invite_default_max_uses integer DEFAULT 1 NOT NULL,
    enrollment_invite_default_expiry_hours integer DEFAULT 72 CONSTRAINT security_policies_enrollment_invite_default_expiry_hou_not_null NOT NULL,
    enrollment_allowed_domains text[] DEFAULT '{}'::text[] NOT NULL,
    enrollment_track_source boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT security_policies_pkey PRIMARY KEY (id)
);

CREATE TABLE upstream_providers (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    protocol character varying(20) NOT NULL,
    trust_category character varying(20) DEFAULT 'social'::character varying NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    client_id character varying(255) NOT NULL,
    client_secret bytea NOT NULL,
    discovery_url text,
    authorization_endpoint text,
    token_endpoint text,
    userinfo_endpoint text,
    scopes jsonb DEFAULT '["openid", "profile", "email"]'::jsonb NOT NULL,
    show_on_login boolean DEFAULT true NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    logo_url text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT upstream_providers_protocol_check CHECK (((protocol)::text = ANY ((ARRAY['oidc'::character varying, 'oauth2'::character varying])::text[]))),
    CONSTRAINT upstream_providers_revision_check CHECK ((revision >= 0)),
    CONSTRAINT upstream_providers_trust_category_check CHECK (((trust_category)::text = ANY ((ARRAY['social'::character varying, 'corporate'::character varying, 'government'::character varying, 'financial'::character varying])::text[]))),
    CONSTRAINT upstream_providers_name_key UNIQUE (name),
    CONSTRAINT upstream_providers_pkey PRIMARY KEY (id)
);

CREATE TABLE closure_requests (
    profile_id uuid NOT NULL,
    mode character varying(30) NOT NULL,
    closure_reason text,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    grace_period_end timestamp with time zone,
    export_status character varying(20) DEFAULT 'not_started'::character varying NOT NULL,
    cancel_count integer DEFAULT 0 NOT NULL,
    legal_hold jsonb,
    CONSTRAINT closure_requests_export_status_check CHECK (((export_status)::text = ANY ((ARRAY['not_started'::character varying, 'preparing'::character varying, 'ready'::character varying, 'downloaded'::character varying, 'expired'::character varying])::text[]))),
    CONSTRAINT closure_requests_mode_check CHECK (((mode)::text = ANY ((ARRAY['voluntary'::character varying, 'gdpr_erasure'::character varying, 'admin_termination'::character varying, 'regulatory_order'::character varying])::text[]))),
    CONSTRAINT closure_requests_pkey PRIMARY KEY (profile_id),
    CONSTRAINT closure_requests_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id)
);

CREATE TABLE consents (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    client_id text NOT NULL,
    status text DEFAULT 'requested'::text NOT NULL,
    consented_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT consents_status_check CHECK ((status = ANY (ARRAY['requested'::text, 'active'::text, 'revoked'::text, 'expired'::text]))),
    CONSTRAINT consents_pkey PRIMARY KEY (id),
    CONSTRAINT consents_profile_id_client_id_key UNIQUE (profile_id, client_id),
    CONSTRAINT consents_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE credentials (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    credential_type character varying(50) NOT NULL,
    data bytea NOT NULL,
    label character varying(255),
    policy_version integer,
    zkpp_verified boolean DEFAULT false NOT NULL,
    opaque_curve smallint,
    legacy_algorithm character varying(50),
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    opaque_credential_identifier bytea,
    zkpp_artifact bytea,
    CONSTRAINT credentials_opaque_credential_identifier_check CHECK ((octet_length(opaque_credential_identifier) = 16)),
    CONSTRAINT credentials_policy_evidence CHECK (((zkpp_verified AND (policy_version IS NOT NULL) AND (zkpp_artifact IS NOT NULL)) OR ((NOT zkpp_verified) AND (policy_version IS NULL) AND (zkpp_artifact IS NULL)))),
    CONSTRAINT credentials_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'revoked'::character varying])::text[]))),
    CONSTRAINT credentials_status_known CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'revoked'::character varying])::text[]))),
    CONSTRAINT credentials_type_known CHECK (((credential_type)::text = ANY ((ARRAY['opaque'::character varying, 'webauthn'::character varying, 'totp'::character varying, 'recovery'::character varying, 'legacy_hash'::character varying])::text[]))),
    CONSTRAINT credentials_zkpp_artifact_check CHECK ((octet_length(zkpp_artifact) = 32)),
    CONSTRAINT credentials_pkey PRIMARY KEY (id),
    CONSTRAINT credentials_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE email_policy_dispositions (
    principal_id uuid NOT NULL,
    from_revision bigint NOT NULL,
    to_revision bigint NOT NULL,
    disposition text NOT NULL,
    reason text NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT email_policy_dispositions_disposition_check CHECK ((disposition = ANY (ARRAY['migrated'::text, 'quarantined'::text]))),
    CONSTRAINT email_policy_dispositions_pkey PRIMARY KEY (principal_id),
    CONSTRAINT email_policy_dispositions_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
);

CREATE TABLE export_jobs (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    format text NOT NULL,
    status text NOT NULL,
    archive_path text,
    size_bytes bigint,
    checksum_sha256 text,
    created_at timestamp with time zone NOT NULL,
    ready_at timestamp with time zone,
    expires_at timestamp with time zone,
    CONSTRAINT export_jobs_format_check CHECK ((format = 'json'::text)),
    CONSTRAINT export_jobs_size_bytes_check CHECK (((size_bytes IS NULL) OR (size_bytes >= 0))),
    CONSTRAINT export_jobs_status_check CHECK ((status = ANY (ARRAY['not_started'::text, 'preparing'::text, 'ready'::text, 'downloaded'::text, 'expired'::text]))),
    CONSTRAINT export_jobs_pkey PRIMARY KEY (id),
    CONSTRAINT export_jobs_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE notification_preferences (
    profile_id uuid NOT NULL,
    preferences jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT notification_preferences_pkey PRIMARY KEY (profile_id),
    CONSTRAINT notification_preferences_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE oidc_issuers (
    id uuid NOT NULL,
    handle text NOT NULL,
    canonical_url text NOT NULL,
    authority text NOT NULL,
    recipient_org uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT oidc_issuers_authority_check CHECK ((authority = 'local'::text)),
    CONSTRAINT oidc_issuers_authority_recipient_org_key UNIQUE (authority, recipient_org),
    CONSTRAINT oidc_issuers_canonical_url_key UNIQUE (canonical_url),
    CONSTRAINT oidc_issuers_handle_key UNIQUE (handle),
    CONSTRAINT oidc_issuers_pkey PRIMARY KEY (id),
    CONSTRAINT oidc_issuers_recipient_org_fkey FOREIGN KEY (recipient_org) REFERENCES organizations(id)
);

CREATE TABLE password_histories (
    owner_id uuid NOT NULL,
    revision bigint NOT NULL,
    CONSTRAINT password_histories_revision_check CHECK ((revision > 0)),
    CONSTRAINT password_histories_pkey PRIMARY KEY (owner_id),
    CONSTRAINT password_histories_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE password_reset_sessions (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    email character varying(255) NOT NULL,
    token_hash character varying(255) NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    shard_downloaded boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT password_reset_sessions_pkey PRIMARY KEY (id),
    CONSTRAINT password_reset_sessions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE personal_access_tokens (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    token_hash character varying(64) NOT NULL,
    token_prefix character varying(20) NOT NULL,
    scopes text DEFAULT ''::text NOT NULL,
    ip_allowlist text DEFAULT ''::text NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    last_used_ip character varying(45),
    use_count bigint DEFAULT 0 NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by character varying(255),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT personal_access_tokens_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'revoked'::character varying, 'expired'::character varying])::text[]))),
    CONSTRAINT personal_access_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT personal_access_tokens_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE principal_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    principal_id uuid NOT NULL,
    profile_id uuid CONSTRAINT principal_bindings_subject_id_not_null NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    source_field text,
    source_email_id uuid,
    source_phone_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT principal_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT uq_principal_binding UNIQUE (principal_id, profile_id),
    CONSTRAINT principal_bindings_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
);

CREATE TABLE profile_blobs (
    profile_id uuid NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    storage_status text DEFAULT 'local'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT profile_blobs_pkey PRIMARY KEY (profile_id),
    CONSTRAINT profile_blobs_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE profile_emails (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    email character varying(255) NOT NULL,
    label character varying(50) DEFAULT 'personal'::character varying NOT NULL,
    custom_label character varying(100),
    is_primary boolean DEFAULT false NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT profile_emails_pkey PRIMARY KEY (id),
    CONSTRAINT profile_emails_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE profile_locations (
    profile_id uuid NOT NULL,
    country character varying(2) NOT NULL,
    latitude double precision NOT NULL,
    longitude double precision NOT NULL,
    login_count integer DEFAULT 1 NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    designated boolean DEFAULT false NOT NULL,
    CONSTRAINT profile_locations_pkey PRIMARY KEY (profile_id, country),
    CONSTRAINT profile_locations_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE profile_metadata (
    profile_id uuid NOT NULL,
    key text NOT NULL,
    value jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT profile_metadata_pkey PRIMARY KEY (profile_id, key),
    CONSTRAINT profile_metadata_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE profile_phones (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    e164 bigint NOT NULL,
    extension integer,
    label character varying(50) DEFAULT 'mobile'::character varying NOT NULL,
    custom_label character varying(100),
    is_primary boolean DEFAULT false NOT NULL,
    can_receive_sms boolean DEFAULT true NOT NULL,
    can_receive_fax boolean DEFAULT false NOT NULL,
    can_receive_voice boolean DEFAULT true NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT profile_phones_pkey PRIMARY KEY (id),
    CONSTRAINT profile_phones_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE projects (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    owner_id uuid,
    is_system boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT projects_pkey PRIMARY KEY (id),
    CONSTRAINT projects_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES profiles(id) ON DELETE SET NULL
);

CREATE TABLE provisioning_credentials (
    id uuid NOT NULL,
    connector_id uuid NOT NULL,
    status text NOT NULL,
    verifier text NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    kind text NOT NULL,
    CONSTRAINT provisioning_credentials_kind_check CHECK ((kind = ANY (ARRAY['scim_bearer'::text, 'client_secret'::text]))),
    CONSTRAINT provisioning_credentials_status_check CHECK ((status = ANY (ARRAY['active'::text, 'grace_period'::text, 'expired'::text, 'revoked'::text]))),
    CONSTRAINT provisioning_credentials_pkey PRIMARY KEY (id),
    CONSTRAINT provisioning_credentials_verifier_key UNIQUE (verifier),
    CONSTRAINT provisioning_credentials_connector_id_fkey FOREIGN KEY (connector_id) REFERENCES provisioning_connectors(id)
);

CREATE TABLE recovery_backups (
    profile_id uuid NOT NULL,
    encrypted_data_key bytea NOT NULL,
    seed_hash bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT recovery_backups_pkey PRIMARY KEY (profile_id),
    CONSTRAINT recovery_backups_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE recovery_shards (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    shard_type character varying(20) NOT NULL,
    shamir_preset character varying(30) DEFAULT 'owner_cloud_sid'::character varying NOT NULL,
    shard_index smallint NOT NULL,
    encrypted_data bytea,
    server_pepper bytea NOT NULL,
    cloud_hint character varying(255),
    trusted_person_id uuid,
    consumed boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT recovery_shards_pkey PRIMARY KEY (id),
    CONSTRAINT recovery_shards_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT recovery_shards_trusted_person_id_fkey FOREIGN KEY (trusted_person_id) REFERENCES profiles(id) ON DELETE SET NULL
);

CREATE TABLE registration_sources (
    profile_id uuid NOT NULL,
    source_type registration_source_type NOT NULL,
    source_id text NOT NULL,
    referrer_id uuid,
    utm_source text DEFAULT ''::text NOT NULL,
    utm_medium text DEFAULT ''::text NOT NULL,
    utm_campaign text DEFAULT ''::text NOT NULL,
    utm_term text DEFAULT ''::text NOT NULL,
    utm_content text DEFAULT ''::text NOT NULL,
    client_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT registration_sources_pkey PRIMARY KEY (profile_id),
    CONSTRAINT registration_sources_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT registration_sources_referrer_id_fkey FOREIGN KEY (referrer_id) REFERENCES profiles(id)
);

CREATE TABLE service_bindings (
    binding_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    scope text NOT NULL,
    binding_index integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT service_bindings_binding_index_check CHECK ((binding_index >= 0)),
    CONSTRAINT service_bindings_scope_check CHECK ((btrim(scope) <> ''::text)),
    CONSTRAINT service_bindings_pkey PRIMARY KEY (binding_id),
    CONSTRAINT service_bindings_profile_id_binding_index_key UNIQUE (profile_id, binding_index),
    CONSTRAINT service_bindings_profile_id_scope_key UNIQUE (profile_id, scope),
    CONSTRAINT service_bindings_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE sessions (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    client_id character varying(255),
    device_id uuid,
    ip_address inet,
    user_agent text,
    scopes text DEFAULT ''::text NOT NULL,
    assurance_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    is_provisional boolean DEFAULT false NOT NULL,
    passkey_prompt boolean DEFAULT false NOT NULL,
    authenticated_at timestamp with time zone DEFAULT now() NOT NULL,
    amr text DEFAULT ''::text NOT NULL,
    policy_grace boolean DEFAULT false NOT NULL,
    grace_deadline timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_activity_at timestamp with time zone,
    elevation_level text,
    elevation_until timestamp with time zone,
    browser_secret_hash bytea,
    authenticated_by uuid,
    browser_csrf bytea,
    CONSTRAINT sessions_base_assurance CHECK (((assurance_level)::text = ANY ((ARRAY['basic'::character varying, 'standard'::character varying])::text[]))),
    CONSTRAINT sessions_elevation_complete CHECK ((((elevation_level IS NULL) AND (elevation_until IS NULL)) OR ((elevation_level = ANY (ARRAY['elevated'::text, 'critical'::text])) AND (elevation_until IS NOT NULL)))),
    CONSTRAINT sessions_host_address CHECK ((masklen(ip_address) = CASE family(ip_address) WHEN 4 THEN 32 ELSE 128 END)),
    CONSTRAINT sessions_pkey PRIMARY KEY (id),
    CONSTRAINT sessions_authenticated_by_fkey FOREIGN KEY (authenticated_by) REFERENCES sessions(id) ON DELETE SET NULL,
    CONSTRAINT sessions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE upstream_identities (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    upstream_subject character varying(255) NOT NULL,
    upstream_issuer character varying(255),
    upstream_email character varying(255),
    upstream_name character varying(255),
    upstream_picture text,
    linked_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at timestamp with time zone,
    login_count bigint DEFAULT 0 NOT NULL,
    CONSTRAINT upstream_identities_pkey PRIMARY KEY (id),
    CONSTRAINT upstream_identities_profile_id_provider_id_key UNIQUE (profile_id, provider_id),
    CONSTRAINT upstream_identities_provider_id_upstream_subject_key UNIQUE (provider_id, upstream_subject),
    CONSTRAINT upstream_identities_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT upstream_identities_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES upstream_providers(id) ON DELETE CASCADE
);

CREATE TABLE webauthn_user_handles (
    profile_id uuid NOT NULL,
    rp_id text NOT NULL,
    user_handle bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT webauthn_user_handles_user_handle_check CHECK ((octet_length(user_handle) = 16)),
    CONSTRAINT webauthn_user_handles_pkey PRIMARY KEY (profile_id, rp_id),
    CONSTRAINT webauthn_user_handles_rp_id_user_handle_key UNIQUE (rp_id, user_handle),
    CONSTRAINT webauthn_user_handles_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE access_requests (
    id uuid NOT NULL,
    requester_id uuid NOT NULL,
    project_id uuid NOT NULL,
    role_key text NOT NULL,
    justification text,
    requested_duration_hours integer,
    status text DEFAULT 'pending'::text NOT NULL,
    reviewed_by uuid,
    review_comment text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_at timestamp with time zone,
    expires_at timestamp with time zone,
    CONSTRAINT access_requests_pkey PRIMARY KEY (id),
    CONSTRAINT access_requests_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT access_requests_requester_id_fkey FOREIGN KEY (requester_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT access_requests_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES profiles(id)
);

CREATE TABLE applications (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    name text NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    system_integration text,
    CONSTRAINT applications_revision_check CHECK ((revision >= 0)),
    CONSTRAINT applications_id_project_id_key UNIQUE (id, project_id),
    CONSTRAINT applications_pkey PRIMARY KEY (id),
    CONSTRAINT applications_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE TABLE branding_configs (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    data jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT branding_configs_revision_check CHECK ((revision >= 0)),
    CONSTRAINT branding_configs_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'archived'::text]))),
    CONSTRAINT branding_configs_pkey PRIMARY KEY (id),
    CONSTRAINT branding_configs_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE claim_grants (
    id uuid NOT NULL,
    consent_id uuid NOT NULL,
    claim_name text NOT NULL,
    claim_type text DEFAULT 'data'::text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT claim_grants_claim_type_check CHECK ((claim_type = ANY (ARRAY['data'::text, 'attestation'::text]))),
    CONSTRAINT claim_grants_consent_id_claim_name_key UNIQUE (consent_id, claim_name),
    CONSTRAINT claim_grants_pkey PRIMARY KEY (id),
    CONSTRAINT claim_grants_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES consents(id) ON DELETE CASCADE
);

CREATE TABLE groups (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    parent_group_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT groups_pkey PRIMARY KEY (id),
    CONSTRAINT groups_project_id_name_key UNIQUE (project_id, name),
    CONSTRAINT groups_parent_group_id_fkey FOREIGN KEY (parent_group_id) REFERENCES groups(id) ON DELETE SET NULL,
    CONSTRAINT groups_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE initial_access_tokens (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    max_clients integer NOT NULL,
    clients_registered integer DEFAULT 0 NOT NULL,
    allowed_scopes text DEFAULT ''::text NOT NULL,
    allowed_grant_types text DEFAULT ''::text NOT NULL,
    allowed_redirect_patterns text DEFAULT ''::text NOT NULL,
    created_by text NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT initial_access_tokens_clients_registered_check CHECK ((clients_registered >= 0)),
    CONSTRAINT initial_access_tokens_max_clients_check CHECK ((max_clients >= 0)),
    CONSTRAINT initial_access_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT initial_access_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT initial_access_tokens_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE machine_users (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    machine_type character varying(20) DEFAULT 'service'::character varying NOT NULL,
    owner_type character varying(20) DEFAULT 'profile'::character varying NOT NULL,
    owner_id character varying(255) NOT NULL,
    client_id character varying(255) NOT NULL,
    display_name character varying(255) NOT NULL,
    description text,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    scopes text DEFAULT ''::text NOT NULL,
    ip_allowlist text DEFAULT ''::text NOT NULL,
    rate_limit_rpm integer DEFAULT 0 NOT NULL,
    max_token_lifetime integer,
    last_used_at timestamp with time zone,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT machine_users_machine_type_check CHECK (((machine_type)::text = ANY ((ARRAY['service'::character varying, 'bot'::character varying, 'agent'::character varying])::text[]))),
    CONSTRAINT machine_users_owner_type_check CHECK (((owner_type)::text = ANY ((ARRAY['profile'::character varying, 'organization'::character varying, 'system'::character varying])::text[]))),
    CONSTRAINT machine_users_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'suspended'::character varying, 'expired'::character varying, 'deleted'::character varying])::text[]))),
    CONSTRAINT machine_users_client_id_key UNIQUE (client_id),
    CONSTRAINT machine_users_pkey PRIMARY KEY (id),
    CONSTRAINT machine_users_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE oidc_issuer_signing_keys (
    issuer_id uuid NOT NULL,
    generation integer NOT NULL,
    key_id text NOT NULL,
    public_key bytea NOT NULL,
    sealed_private_key bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT oidc_issuer_signing_keys_generation_check CHECK ((generation >= 1)),
    CONSTRAINT oidc_issuer_signing_keys_public_key_check CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT oidc_issuer_signing_keys_pkey PRIMARY KEY (issuer_id, generation),
    CONSTRAINT oidc_issuer_signing_keys_issuer_id_fkey FOREIGN KEY (issuer_id) REFERENCES oidc_issuers(id)
);

CREATE TABLE password_history_epochs (
    id uuid NOT NULL,
    owner_id uuid NOT NULL,
    suite text NOT NULL,
    public_key bytea NOT NULL,
    ksf_memory_kib integer NOT NULL,
    ksf_passes integer NOT NULL,
    ksf_lanes integer NOT NULL,
    ksf_salt bytea NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT password_history_epochs_ksf_lanes_check CHECK ((ksf_lanes > 0)),
    CONSTRAINT password_history_epochs_ksf_memory_kib_check CHECK ((ksf_memory_kib > 0)),
    CONSTRAINT password_history_epochs_ksf_passes_check CHECK ((ksf_passes > 0)),
    CONSTRAINT password_history_epochs_ksf_salt_check CHECK ((octet_length(ksf_salt) = 32)),
    CONSTRAINT password_history_epochs_public_key_check CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT password_history_epochs_status_check CHECK ((status = ANY (ARRAY['active'::text, 'compare_only'::text, 'retired'::text]))),
    CONSTRAINT password_history_epochs_suite_check CHECK ((suite = 'pallas-poseidon-v1'::text)),
    CONSTRAINT password_history_epochs_pkey PRIMARY KEY (id),
    CONSTRAINT password_history_epochs_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES password_histories(owner_id) ON DELETE CASCADE
);

CREATE TABLE profile_grants (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    role_keys text DEFAULT ''::text NOT NULL,
    granted_by text,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT profile_grants_pkey PRIMARY KEY (id),
    CONSTRAINT profile_grants_project_id_profile_id_key UNIQUE (project_id, profile_id),
    CONSTRAINT profile_grants_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT profile_grants_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE roles (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    permissions text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    key text DEFAULT ''::text NOT NULL,
    group_label text,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT roles_revision_check CHECK ((revision >= 0)),
    CONSTRAINT roles_pkey PRIMARY KEY (id),
    CONSTRAINT roles_project_id_key_key UNIQUE (project_id, key),
    CONSTRAINT roles_project_id_name_key UNIQUE (project_id, name),
    CONSTRAINT roles_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE scim_outbound_targets (
    id uuid NOT NULL,
    client_id text NOT NULL,
    project_id uuid NOT NULL,
    display_name text NOT NULL,
    endpoint_url text NOT NULL,
    auth_config jsonb NOT NULL,
    attribute_mapping jsonb DEFAULT '{"mappings": []}'::jsonb NOT NULL,
    group_push jsonb DEFAULT '{"enabled": false, "mapping": []}'::jsonb NOT NULL,
    sync_config jsonb DEFAULT '{"max_retry_attempts": 5, "retry_backoff_base_secs": 1}'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scim_outbound_targets_pkey PRIMARY KEY (id),
    CONSTRAINT scim_outbound_targets_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE TABLE group_members (
    group_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_members_pkey PRIMARY KEY (group_id, profile_id),
    CONSTRAINT group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    CONSTRAINT group_members_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE impersonation_grants (
    id uuid NOT NULL,
    machine_user_id uuid NOT NULL,
    target_type character varying(20) NOT NULL,
    target character varying(255) NOT NULL,
    allowed_scopes text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT impersonation_grants_target_type_check CHECK (((target_type)::text = ANY ((ARRAY['role'::character varying, 'user'::character varying])::text[]))),
    CONSTRAINT impersonation_grants_machine_user_id_target_type_target_key UNIQUE (machine_user_id, target_type, target),
    CONSTRAINT impersonation_grants_pkey PRIMARY KEY (id),
    CONSTRAINT impersonation_grants_machine_user_id_fkey FOREIGN KEY (machine_user_id) REFERENCES machine_users(id) ON DELETE CASCADE
);

CREATE TABLE invites (
    id uuid NOT NULL,
    code character varying(8) NOT NULL,
    created_by uuid,
    created_by_name text DEFAULT ''::text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    max_uses integer DEFAULT 1 NOT NULL,
    use_count integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by_machine uuid,
    CONSTRAINT invites_one_creator CHECK (((created_by IS NULL) <> (created_by_machine IS NULL))),
    CONSTRAINT invites_pkey PRIMARY KEY (id),
    CONSTRAINT invites_created_by_fkey FOREIGN KEY (created_by) REFERENCES profiles(id),
    CONSTRAINT invites_created_by_machine_fkey FOREIGN KEY (created_by_machine) REFERENCES machine_users(id)
);

CREATE TABLE machine_user_credentials (
    kid character varying(255) NOT NULL,
    machine_user_id uuid NOT NULL,
    credential_type character varying(30) NOT NULL,
    credential_data text NOT NULL,
    algorithm character varying(20),
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT machine_user_credentials_credential_type_check CHECK (((credential_type)::text = ANY ((ARRAY['client_secret'::character varying, 'private_key_jwt'::character varying, 'mtls'::character varying, 'workload_identity'::character varying])::text[]))),
    CONSTRAINT machine_user_credentials_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'grace_period'::character varying, 'expired'::character varying, 'revoked'::character varying])::text[]))),
    CONSTRAINT machine_user_credentials_pkey PRIMARY KEY (kid),
    CONSTRAINT machine_user_credentials_machine_user_id_fkey FOREIGN KEY (machine_user_id) REFERENCES machine_users(id) ON DELETE CASCADE
);

CREATE TABLE password_history_entries (
    epoch_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    seq bigint NOT NULL,
    entry bytea NOT NULL,
    operation_id uuid NOT NULL,
    policy_version integer NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT password_history_entries_entry_check CHECK ((octet_length(entry) = 32)),
    CONSTRAINT password_history_entries_pkey PRIMARY KEY (epoch_id, seq),
    CONSTRAINT password_history_entries_epoch_id_fkey FOREIGN KEY (epoch_id) REFERENCES password_history_epochs(id) ON DELETE CASCADE,
    CONSTRAINT password_history_entries_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES password_histories(owner_id) ON DELETE CASCADE
);

CREATE TABLE protected_resources (
    id uuid NOT NULL,
    application_id uuid,
    issuer_id uuid NOT NULL,
    indicator text NOT NULL,
    scopes text DEFAULT ''::text NOT NULL,
    state text NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT protected_resources_check CHECK (((state = 'retired'::text) = (application_id IS NULL))),
    CONSTRAINT protected_resources_revision_check CHECK ((revision >= 0)),
    CONSTRAINT protected_resources_state_check CHECK ((state = ANY (ARRAY['active'::text, 'inactive'::text, 'retired'::text]))),
    CONSTRAINT protected_resources_application_id_key UNIQUE (application_id),
    CONSTRAINT protected_resources_issuer_id_indicator_key UNIQUE (issuer_id, indicator),
    CONSTRAINT protected_resources_pkey PRIMARY KEY (id),
    CONSTRAINT protected_resources_application_id_fkey FOREIGN KEY (application_id) REFERENCES applications(id),
    CONSTRAINT protected_resources_issuer_id_fkey FOREIGN KEY (issuer_id) REFERENCES oidc_issuers(id)
);

CREATE TABLE scim_outbound_dlq (
    id uuid NOT NULL,
    target_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    sid_entity_id uuid NOT NULL,
    entity_type text NOT NULL,
    error text NOT NULL,
    attempts integer DEFAULT 1 NOT NULL,
    first_attempt timestamp with time zone DEFAULT now() NOT NULL,
    last_attempt timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scim_outbound_dlq_entity_type_check CHECK ((entity_type = ANY (ARRAY['user'::text, 'group'::text]))),
    CONSTRAINT scim_outbound_dlq_pkey PRIMARY KEY (id),
    CONSTRAINT scim_outbound_dlq_target_id_fkey FOREIGN KEY (target_id) REFERENCES scim_outbound_targets(id) ON DELETE CASCADE
);

CREATE TABLE scim_outbound_records (
    target_id uuid NOT NULL,
    sid_entity_id uuid NOT NULL,
    entity_type text NOT NULL,
    downstream_id text NOT NULL,
    last_synced_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error text,
    failure_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scim_outbound_records_entity_type_check CHECK ((entity_type = ANY (ARRAY['user'::text, 'group'::text]))),
    CONSTRAINT scim_outbound_records_pkey PRIMARY KEY (target_id, sid_entity_id, entity_type),
    CONSTRAINT scim_outbound_records_target_id_fkey FOREIGN KEY (target_id) REFERENCES scim_outbound_targets(id) ON DELETE CASCADE
);

CREATE TABLE authorization_codes (
    code_hash bytea NOT NULL,
    profile_id uuid NOT NULL,
    client_id character varying(255) NOT NULL,
    redirect_uri text NOT NULL,
    scopes text DEFAULT ''::text NOT NULL,
    code_challenge character varying(128),
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    used boolean DEFAULT false NOT NULL,
    session_id uuid,
    nonce text,
    resource_id uuid NOT NULL,
    authorizing_session_id uuid NOT NULL,
    authenticated_at timestamp with time zone NOT NULL,
    amr text NOT NULL,
    assurance_level text NOT NULL,
    elevation_level text,
    elevation_until timestamp with time zone,
    CONSTRAINT authorization_codes_pkey PRIMARY KEY (code_hash),
    CONSTRAINT authorization_codes_authorizing_session_id_fkey FOREIGN KEY (authorizing_session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    CONSTRAINT authorization_codes_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT authorization_codes_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES protected_resources(id)
);

CREATE TABLE cedar_policies (
    id uuid NOT NULL,
    project_id uuid,
    resource_id uuid,
    name text NOT NULL,
    description text,
    policy_text text NOT NULL,
    effect text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT cedar_policies_check CHECK (((project_id IS NULL) OR (resource_id IS NULL))),
    CONSTRAINT cedar_policies_revision_check CHECK ((revision >= 0)),
    CONSTRAINT cedar_policies_pkey PRIMARY KEY (id),
    CONSTRAINT cedar_policies_project_id_resource_id_name_key UNIQUE NULLS NOT DISTINCT (project_id, resource_id, name),
    CONSTRAINT cedar_policies_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT cedar_policies_resource_fk FOREIGN KEY (resource_id) REFERENCES protected_resources(id)
);

CREATE TABLE device_authorization_codes (
    id uuid NOT NULL,
    client_id character varying(255) NOT NULL,
    device_code_hash bytea NOT NULL,
    user_code character varying(16) NOT NULL,
    scope text,
    status character varying(32) DEFAULT 'pending'::character varying NOT NULL,
    authorized_by uuid,
    project_id uuid NOT NULL,
    interval_secs integer DEFAULT 5 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    authorized_at timestamp with time zone,
    last_polled_at timestamp with time zone,
    redeemed_session_id uuid,
    resource_id uuid NOT NULL,
    CONSTRAINT device_authorization_codes_status_known CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'authorized'::character varying, 'denied'::character varying, 'expired'::character varying, 'redeemed'::character varying])::text[]))),
    CONSTRAINT device_authorization_codes_pkey PRIMARY KEY (id),
    CONSTRAINT device_authorization_codes_authorized_by_fkey FOREIGN KEY (authorized_by) REFERENCES profiles(id) ON DELETE SET NULL,
    CONSTRAINT device_authorization_codes_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT device_authorization_codes_redeemed_session_id_fkey FOREIGN KEY (redeemed_session_id) REFERENCES sessions(id) ON DELETE SET NULL,
    CONSTRAINT device_authorization_codes_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES protected_resources(id)
);

CREATE TABLE invite_redemptions (
    invite_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    redeemed_at timestamp with time zone DEFAULT now() NOT NULL,
    credential_id uuid,
    CONSTRAINT invite_redemptions_pkey PRIMARY KEY (invite_id, profile_id),
    CONSTRAINT invite_redemptions_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE SET NULL,
    CONSTRAINT invite_redemptions_invite_id_fkey FOREIGN KEY (invite_id) REFERENCES invites(id) ON DELETE CASCADE,
    CONSTRAINT invite_redemptions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE oauth2_clients (
    client_id character varying(255) NOT NULL,
    client_secret_hash bytea,
    redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    allowed_scopes text DEFAULT 'openid profile email'::text NOT NULL,
    grant_types text DEFAULT 'authorization_code'::text NOT NULL,
    client_name character varying(255) NOT NULL,
    active boolean DEFAULT true NOT NULL,
    project_id uuid DEFAULT '00000000-0000-0000-0000-000000000000'::uuid NOT NULL,
    application_type character varying(32) DEFAULT 'web'::character varying NOT NULL,
    required_acr character varying(20),
    required_amr text DEFAULT ''::text NOT NULL,
    enforcement_mode character varying(20) DEFAULT 'audit'::character varying NOT NULL,
    min_device_assurance character varying(20),
    require_verified_email boolean,
    require_verified_phone boolean,
    backchannel_logout_uri text,
    backchannel_logout_session_required boolean DEFAULT false NOT NULL,
    claim_mappings text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    logo_uri text,
    login_strategy text DEFAULT 'local_first'::text NOT NULL,
    show_federation_button boolean DEFAULT true NOT NULL,
    federation_timeout_ms integer DEFAULT 500 NOT NULL,
    unified_input boolean DEFAULT false NOT NULL,
    subject_type character varying(20) DEFAULT 'public'::character varying NOT NULL,
    sector_identifier_uri text,
    token_endpoint_auth_method character varying(32) DEFAULT 'client_secret_post'::character varying NOT NULL,
    response_types text DEFAULT 'code'::text NOT NULL,
    contacts text[] DEFAULT '{}'::text[] NOT NULL,
    registration_access_token_hash bytea,
    org_id uuid,
    client_id_issued_at timestamp with time zone DEFAULT now() NOT NULL,
    client_secret_expires_at timestamp with time zone,
    registration_iat uuid,
    revision bigint DEFAULT 0 NOT NULL,
    application_id uuid NOT NULL,
    default_resource uuid,
    jwks text,
    post_logout_redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    CONSTRAINT oauth2_clients_revision_non_negative CHECK ((revision >= 0)),
    CONSTRAINT oauth2_clients_application_unique UNIQUE (application_id),
    CONSTRAINT oauth2_clients_pkey PRIMARY KEY (client_id),
    CONSTRAINT oauth2_clients_application_fk FOREIGN KEY (application_id, project_id) REFERENCES applications(id, project_id),
    CONSTRAINT oauth2_clients_default_resource_fkey FOREIGN KEY (default_resource) REFERENCES protected_resources(id),
    CONSTRAINT oauth2_clients_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id),
    CONSTRAINT oauth2_clients_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE TABLE refresh_tokens (
    id uuid NOT NULL,
    token_hash bytea NOT NULL,
    session_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    client_id character varying(255) NOT NULL,
    scopes text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    replaced_by uuid,
    family_id uuid NOT NULL,
    grace_expires_at timestamp with time zone,
    dpop_jkt text,
    resource_id uuid NOT NULL,
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT refresh_tokens_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT refresh_tokens_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES protected_resources(id),
    CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE resource_access (
    oauth_client_id text,
    machine_client_id character varying(255),
    client_id text GENERATED ALWAYS AS (COALESCE(oauth_client_id, (machine_client_id)::text)) STORED NOT NULL,
    resource_id uuid NOT NULL,
    scopes text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT resource_access_check CHECK ((num_nonnulls(oauth_client_id, machine_client_id) = 1)),
    CONSTRAINT resource_access_pkey PRIMARY KEY (client_id, resource_id),
    CONSTRAINT resource_access_machine_client_id_fkey FOREIGN KEY (machine_client_id) REFERENCES machine_users(client_id) ON DELETE CASCADE,
    CONSTRAINT resource_access_oauth_client_id_fkey FOREIGN KEY (oauth_client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    CONSTRAINT resource_access_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES protected_resources(id)
);

CREATE TABLE role_assignments (
    id uuid NOT NULL,
    profile_id uuid,
    group_id uuid,
    machine_user_id uuid,
    role_id uuid NOT NULL,
    scope text,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    oauth_client_id text,
    provisioning_connector_id uuid,
    granted_by text,
    basis_assignment_id uuid,
    depends_on_assignment_id uuid,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT chk_principal CHECK ((num_nonnulls(profile_id, group_id, machine_user_id, oauth_client_id, provisioning_connector_id) = 1)),
    CONSTRAINT chk_role_assignment_provenance CHECK (((granted_by IS NOT NULL) OR ((basis_assignment_id IS NULL) AND (depends_on_assignment_id IS NULL)))),
    CONSTRAINT role_assignments_pkey PRIMARY KEY (id),
    CONSTRAINT role_assignments_depends_on_assignment_id_fkey FOREIGN KEY (depends_on_assignment_id) REFERENCES role_assignments(id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_group_id_fkey FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_oauth_client_id_fkey FOREIGN KEY (oauth_client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_provisioning_connector_id_fkey FOREIGN KEY (provisioning_connector_id) REFERENCES provisioning_connectors(id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_role_id_fkey FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE role_assignment_admin (
    assignment_id uuid NOT NULL,
    recipient_group_id uuid,
    max_validity_secs bigint NOT NULL,
    CONSTRAINT role_assignment_admin_max_validity_secs_check CHECK ((max_validity_secs > 0)),
    CONSTRAINT role_assignment_admin_pkey PRIMARY KEY (assignment_id),
    CONSTRAINT role_assignment_admin_assignment_id_fkey FOREIGN KEY (assignment_id) REFERENCES role_assignments(id) ON DELETE CASCADE,
    CONSTRAINT role_assignment_admin_recipient_group_id_fkey FOREIGN KEY (recipient_group_id) REFERENCES groups(id) ON DELETE RESTRICT
);

CREATE TABLE role_assignment_ceilings (
    assignment_id uuid NOT NULL,
    permission text NOT NULL,
    CONSTRAINT role_assignment_ceilings_pkey PRIMARY KEY (assignment_id, permission),
    CONSTRAINT role_assignment_ceilings_assignment_id_fkey FOREIGN KEY (assignment_id) REFERENCES role_assignments(id) ON DELETE CASCADE
);

CREATE TABLE role_assignment_admin_entries (
    assignment_id uuid NOT NULL,
    kind text NOT NULL,
    value text NOT NULL,
    CONSTRAINT role_assignment_admin_entries_check CHECK (((kind <> 'operation'::text) OR (value = ANY (ARRAY['assign'::text, 'revoke'::text, 'edit_role'::text, 'redelegate'::text])))),
    CONSTRAINT role_assignment_admin_entries_check1 CHECK (((kind <> 'recipient_kind'::text) OR (value = ANY (ARRAY['profile'::text, 'group'::text, 'machine_user'::text, 'oauth_client'::text])))),
    CONSTRAINT role_assignment_admin_entries_kind_check CHECK ((kind = ANY (ARRAY['operation'::text, 'recipient_kind'::text, 'permission'::text]))),
    CONSTRAINT role_assignment_admin_entries_pkey PRIMARY KEY (assignment_id, kind, value),
    CONSTRAINT role_assignment_admin_entries_assignment_id_fkey FOREIGN KEY (assignment_id) REFERENCES role_assignment_admin(assignment_id) ON DELETE CASCADE
);

CREATE TABLE role_assignment_admin_roles (
    assignment_id uuid NOT NULL,
    role_id uuid NOT NULL,
    CONSTRAINT role_assignment_admin_roles_pkey PRIMARY KEY (assignment_id, role_id),
    CONSTRAINT role_assignment_admin_roles_assignment_id_fkey FOREIGN KEY (assignment_id) REFERENCES role_assignment_admin(assignment_id) ON DELETE CASCADE,
    CONSTRAINT role_assignment_admin_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE role_assignment_policy_admin (
    assignment_id uuid NOT NULL,
    operation text NOT NULL,
    CONSTRAINT role_assignment_policy_admin_operation_check CHECK ((operation = ANY (ARRAY['read'::text, 'edit'::text, 'redelegate'::text]))),
    CONSTRAINT role_assignment_policy_admin_pkey PRIMARY KEY (assignment_id, operation),
    CONSTRAINT role_assignment_policy_admin_assignment_id_fkey FOREIGN KEY (assignment_id) REFERENCES role_assignments(id) ON DELETE CASCADE
);

CREATE VIEW profiles_view AS
 SELECT p.id,
    NULLIF(concat_ws(' '::text, p.given_name, p.middle_name, p.family_name), ''::text) AS display_name,
    e.email,
    p.status AS profile_status,
    p.created_at,
    p.updated_at
   FROM (profiles p
     LEFT JOIN profile_emails e ON (((e.profile_id = p.id) AND e.is_primary)));

CREATE UNIQUE INDEX applications_system_integration ON applications USING btree (system_integration) WHERE (system_integration IS NOT NULL);

CREATE INDEX idx_audit_action ON audit_records USING btree (action);

CREATE INDEX idx_audit_actor ON audit_records USING btree (actor_id);

CREATE INDEX idx_audit_chain_id ON audit_records USING btree (chain_id, sequence);

CREATE INDEX idx_audit_timestamp ON audit_records USING btree ("timestamp");

CREATE INDEX idx_access_requests_requester ON access_requests USING btree (requester_id);

CREATE INDEX idx_access_requests_status ON access_requests USING btree (status);

CREATE INDEX idx_anomaly_events_profile_id ON anomaly_events USING btree (profile_id) WHERE (profile_id <> ''::text);

CREATE INDEX idx_anomaly_events_rule_id ON anomaly_events USING btree (rule_id);

CREATE INDEX idx_anomaly_events_timestamp ON anomaly_events USING btree ("timestamp" DESC);

CREATE INDEX idx_applications_project ON applications USING btree (project_id);

CREATE INDEX idx_auth_codes_expires ON authorization_codes USING btree (expires_at);

CREATE INDEX idx_branding_configs_project_id ON branding_configs USING btree (project_id);

CREATE UNIQUE INDEX idx_branding_configs_published ON branding_configs USING btree (project_id) WHERE (status = 'published'::text);

CREATE INDEX idx_cedar_policies_project_id ON cedar_policies USING btree (project_id);

CREATE INDEX idx_cedar_policies_resource_id ON cedar_policies USING btree (resource_id);

CREATE INDEX idx_claim_grants_consent ON claim_grants USING btree (consent_id);

CREATE INDEX idx_consents_client ON consents USING btree (client_id);

CREATE INDEX idx_consents_profile ON consents USING btree (profile_id);

CREATE INDEX idx_credentials_opaque_curve ON credentials USING btree (opaque_curve) WHERE (opaque_curve IS NOT NULL);

CREATE INDEX idx_credentials_profile_id ON credentials USING btree (profile_id);

CREATE INDEX idx_credentials_profile_type ON credentials USING btree (profile_id, credential_type);

CREATE INDEX idx_credentials_type ON credentials USING btree (credential_type);

CREATE INDEX idx_device_attestations_profile_id ON device_attestations USING btree (profile_id);

CREATE INDEX idx_device_attestations_status ON device_attestations USING btree (status);

CREATE UNIQUE INDEX idx_device_auth_device_code_hash ON device_authorization_codes USING btree (device_code_hash);

CREATE INDEX idx_device_auth_expires_at ON device_authorization_codes USING btree (expires_at) WHERE ((status)::text = 'pending'::text);

CREATE UNIQUE INDEX idx_device_auth_user_code ON device_authorization_codes USING btree (user_code);

CREATE INDEX idx_devices_fingerprint ON devices USING btree (profile_id, fingerprint_hash) WHERE (fingerprint_hash IS NOT NULL);

CREATE INDEX idx_devices_profile_id ON devices USING btree (profile_id);

CREATE INDEX idx_durable_work_open ON durable_work USING btree (kind, not_before) WHERE (state = ANY (ARRAY['pending'::text, 'claimed'::text]));

CREATE INDEX idx_entity_attributes_entity_id ON entity_attributes USING btree (entity_id);

CREATE INDEX idx_export_jobs_profile_created ON export_jobs USING btree (profile_id, created_at DESC);

CREATE INDEX idx_flow_actions_project_flow ON flow_actions USING btree (project_id, flow_type, action_point);

CREATE INDEX idx_group_members_profile_id ON group_members USING btree (profile_id);

CREATE INDEX idx_groups_parent ON groups USING btree (parent_group_id) WHERE (parent_group_id IS NOT NULL);

CREATE INDEX idx_groups_project_id ON groups USING btree (project_id);

CREATE INDEX idx_impersonation_machine ON impersonation_grants USING btree (machine_user_id);

CREATE INDEX idx_initial_access_tokens_project ON initial_access_tokens USING btree (project_id);

CREATE INDEX idx_invite_redemptions_order ON invite_redemptions USING btree (invite_id, redeemed_at, profile_id);

CREATE INDEX idx_invites_active ON invites USING btree (active, created_at DESC);

CREATE UNIQUE INDEX idx_invites_code ON invites USING btree (upper((code)::text));

CREATE INDEX idx_invites_created_by ON invites USING btree (created_by);

CREATE INDEX idx_invites_created_id ON invites USING btree (created_at DESC, id DESC);

CREATE INDEX idx_ip_reputation_score ON ip_reputation USING btree (score DESC) WHERE (score > (0.3)::double precision);

CREATE INDEX idx_ip_reputation_updated ON ip_reputation USING btree (updated_at);

CREATE INDEX idx_machine_creds_user ON machine_user_credentials USING btree (machine_user_id);

CREATE INDEX idx_machine_users_owner ON machine_users USING btree (owner_type, owner_id);

CREATE INDEX idx_machine_users_project ON machine_users USING btree (project_id);

CREATE INDEX idx_magic_link_sessions_email ON magic_link_sessions USING btree (email);

CREATE INDEX idx_magic_link_sessions_expires ON magic_link_sessions USING btree (expires_at);

CREATE INDEX idx_oauth2_clients_project ON oauth2_clients USING btree (project_id);

CREATE INDEX idx_password_reset_sessions_expired ON password_reset_sessions USING btree (expires_at) WHERE ((status)::text = 'pending'::text);

CREATE INDEX idx_password_reset_sessions_profile ON password_reset_sessions USING btree (profile_id, created_at DESC);

CREATE INDEX idx_pat_profile_status ON personal_access_tokens USING btree (profile_id, status);

CREATE UNIQUE INDEX idx_pat_token_hash ON personal_access_tokens USING btree (token_hash);

CREATE INDEX idx_principal_bindings_principal_id ON principal_bindings USING btree (principal_id);

CREATE INDEX idx_principal_bindings_profile ON principal_bindings USING btree (profile_id);

CREATE INDEX idx_principal_quarantine_until ON principal_quarantine USING btree (quarantine_until);

CREATE INDEX idx_principals_assigned_profile_id ON principals USING btree (assigned_profile_id) WHERE (assigned_profile_id IS NOT NULL);

CREATE INDEX idx_principals_type_folded_value ON principals USING btree (principal_type, lower((value COLLATE pg_c_utf8)));

CREATE UNIQUE INDEX idx_principals_type_value ON principals USING btree (principal_type, value);

CREATE INDEX idx_principals_value ON principals USING btree (value);

CREATE INDEX idx_profile_emails_email ON profile_emails USING btree (email);

CREATE UNIQUE INDEX idx_profile_emails_primary ON profile_emails USING btree (profile_id) WHERE (is_primary = true);

CREATE UNIQUE INDEX idx_profile_emails_profile_email ON profile_emails USING btree (profile_id, email);

CREATE INDEX idx_profile_emails_profile_id ON profile_emails USING btree (profile_id);

CREATE INDEX idx_profile_grants_profile_id ON profile_grants USING btree (profile_id);

CREATE INDEX idx_profile_grants_project_id ON profile_grants USING btree (project_id);

CREATE INDEX idx_profile_locations_designated ON profile_locations USING btree (profile_id) WHERE (designated = true);

CREATE INDEX idx_profile_metadata_profile_id ON profile_metadata USING btree (profile_id);

CREATE UNIQUE INDEX idx_profile_phones_primary ON profile_phones USING btree (profile_id) WHERE (is_primary = true);

CREATE UNIQUE INDEX idx_profile_phones_profile_e164 ON profile_phones USING btree (profile_id, e164);

CREATE INDEX idx_profile_phones_profile_id ON profile_phones USING btree (profile_id);

CREATE INDEX idx_profiles_created_id ON profiles USING btree (created_at, id);

CREATE INDEX idx_profiles_migration_pending ON profiles USING btree (migration_pending) WHERE (migration_pending = true);

CREATE INDEX idx_profiles_status ON profiles USING btree (status);

CREATE INDEX idx_profiles_username ON profiles USING btree (username);

CREATE INDEX idx_projects_owner ON projects USING btree (owner_id) WHERE (owner_id IS NOT NULL);

CREATE UNIQUE INDEX idx_provisioning_connectors_client_id ON provisioning_connectors USING btree (client_id);

CREATE INDEX idx_provisioning_connectors_org ON provisioning_connectors USING btree (org_id, created_at DESC);

CREATE INDEX idx_provisioning_credentials_connector ON provisioning_credentials USING btree (connector_id, created_at DESC);

CREATE UNIQUE INDEX idx_recovery_shards_profile_type ON recovery_shards USING btree (profile_id, shard_type);

CREATE INDEX idx_recovery_shards_sid_unconsumed ON recovery_shards USING btree (profile_id) WHERE (((shard_type)::text = 'sid'::text) AND (consumed = false));

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens USING btree (family_id);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens USING btree (token_hash);

CREATE INDEX idx_refresh_tokens_profile ON refresh_tokens USING btree (profile_id);

CREATE INDEX idx_refresh_tokens_session ON refresh_tokens USING btree (session_id);

CREATE INDEX idx_registration_sources_referrer ON registration_sources USING btree (referrer_id) WHERE (referrer_id IS NOT NULL);

CREATE INDEX idx_registration_sources_type_date ON registration_sources USING btree (source_type, created_at DESC);

CREATE INDEX idx_resource_access_resource ON resource_access USING btree (resource_id);

CREATE INDEX idx_role_assignment_admin_roles_role ON role_assignment_admin_roles USING btree (role_id);

CREATE INDEX idx_role_assignments_depends_on ON role_assignments USING btree (depends_on_assignment_id) WHERE (depends_on_assignment_id IS NOT NULL);

CREATE INDEX idx_role_assignments_group_id ON role_assignments USING btree (group_id);

CREATE INDEX idx_role_assignments_machine_user_id ON role_assignments USING btree (machine_user_id);

CREATE INDEX idx_role_assignments_oauth_client_id ON role_assignments USING btree (oauth_client_id);

CREATE INDEX idx_role_assignments_profile_id ON role_assignments USING btree (profile_id);

CREATE INDEX idx_role_assignments_provisioning_connector_id ON role_assignments USING btree (provisioning_connector_id);

CREATE INDEX idx_role_assignments_role_id ON role_assignments USING btree (role_id);

CREATE INDEX idx_roles_project_id ON roles USING btree (project_id);

CREATE INDEX idx_scim_outbound_dlq_target ON scim_outbound_dlq USING btree (target_id);

CREATE INDEX idx_scim_outbound_records_downstream ON scim_outbound_records USING btree (target_id, downstream_id);

CREATE INDEX idx_scim_outbound_targets_project ON scim_outbound_targets USING btree (project_id);

CREATE INDEX idx_security_policies_enrollment_mode ON security_policies USING btree (enrollment_mode);

CREATE INDEX idx_sessions_client_id ON sessions USING btree (client_id) WHERE (client_id IS NOT NULL);

CREATE INDEX idx_sessions_device_id ON sessions USING btree (device_id) WHERE (device_id IS NOT NULL);

CREATE INDEX idx_sessions_device_lookup ON sessions USING btree (profile_id, device_id, created_at DESC) WHERE (device_id IS NOT NULL);

CREATE INDEX idx_sessions_expires_at ON sessions USING btree (expires_at);

CREATE INDEX idx_sessions_profile_id ON sessions USING btree (profile_id);

CREATE INDEX idx_upstream_identities_email ON upstream_identities USING btree (upstream_email) WHERE (upstream_email IS NOT NULL);

CREATE INDEX idx_upstream_identities_profile ON upstream_identities USING btree (profile_id);

CREATE INDEX idx_upstream_providers_display ON upstream_providers USING btree (display_order) WHERE (show_on_login = true);

CREATE INDEX idx_upstream_providers_enabled ON upstream_providers USING btree (enabled) WHERE (enabled = true);

CREATE INDEX operation_results_retain_until ON operation_results USING btree (retain_until) WHERE (retain_until IS NOT NULL);

CREATE UNIQUE INDEX organizations_one_instance ON organizations USING btree (is_instance) WHERE is_instance;

CREATE INDEX password_history_entries_owner ON password_history_entries USING btree (owner_id, seq);

CREATE UNIQUE INDEX password_history_one_active_epoch ON password_history_epochs USING btree (owner_id) WHERE (status = 'active'::text);

CREATE INDEX sessions_authenticated_by ON sessions USING btree (authenticated_by) WHERE (authenticated_by IS NOT NULL);

CREATE UNIQUE INDEX sessions_browser_secret_hash ON sessions USING btree (browser_secret_hash) WHERE (browser_secret_hash IS NOT NULL);

CREATE UNIQUE INDEX uq_credentials_active_opaque ON credentials USING btree (profile_id) WHERE (((credential_type)::text = 'opaque'::text) AND ((status)::text = 'active'::text));

CREATE RULE profiles_view_no_delete AS
    ON DELETE TO profiles_view DO INSTEAD NOTHING;

CREATE RULE profiles_view_no_insert AS
    ON INSERT TO profiles_view DO INSTEAD NOTHING;

CREATE RULE profiles_view_no_update AS
    ON UPDATE TO profiles_view DO INSTEAD NOTHING;

CREATE TRIGGER instance_secrets_no_claim_when_centrally_managed BEFORE INSERT OR UPDATE ON instance_secrets FOR EACH ROW EXECUTE FUNCTION refuse_admin_claim_when_centrally_managed();

CREATE TRIGGER principals_email_policy_fence BEFORE INSERT OR UPDATE OF value, email_policy_revision, principal_type ON principals FOR EACH ROW EXECUTE FUNCTION principals_email_policy_fence();

CREATE TRIGGER trg_audit_records_no_delete BEFORE DELETE ON audit_records FOR EACH ROW EXECUTE FUNCTION audit_records_immutable();

CREATE TRIGGER trg_audit_records_no_update BEFORE UPDATE ON audit_records FOR EACH ROW EXECUTE FUNCTION audit_records_immutable();

CREATE TRIGGER update_profile_emails_updated_at BEFORE UPDATE ON profile_emails FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_profile_phones_updated_at BEFORE UPDATE ON profile_phones FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON profiles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

INSERT INTO projects VALUES ('00000000-0000-0000-0000-000000000000', 'SID', 'Default system project', NULL, true, NOW(), NOW());

INSERT INTO email_policy_activations VALUES ('installation', 1, NOW());

INSERT INTO password_history_write_cutoff VALUES (true, NULL);
