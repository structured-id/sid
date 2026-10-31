-- The password-history evaluator's own store: per-owner VOPRF keys and the
-- lifecycle that decides which replaced keys stay in use. Keyed by the owner's
-- history input domain (32 bytes); it holds no account, entry or credential
-- data and references no table outside this set, so it can live in its own
-- database under its own role. Before the first release a change edits this
-- file and the store is recreated.

CREATE TABLE history_key_abandoned (
    operation_id uuid NOT NULL,
    owner_domain bytea NOT NULL,
    abandoned_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT history_key_abandoned_pkey PRIMARY KEY (operation_id),
    CONSTRAINT history_key_abandoned_owner_domain_check CHECK ((octet_length(owner_domain) = 32))
);

CREATE TABLE history_key_audit (
    id bigserial NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_id text NOT NULL,
    actor_type text NOT NULL,
    action text NOT NULL,
    resource text NOT NULL,
    outcome text NOT NULL,
    metadata jsonb NOT NULL,
    CONSTRAINT history_key_audit_pkey PRIMARY KEY (id)
);

CREATE TABLE history_key_epochs (
    id uuid NOT NULL,
    owner_domain bytea NOT NULL,
    suite text NOT NULL,
    public_key bytea NOT NULL,
    wrapped_key bytea NOT NULL,
    ksf_memory_kib integer NOT NULL,
    ksf_passes integer NOT NULL,
    ksf_lanes integer NOT NULL,
    ksf_salt bytea NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    created_by uuid,
    CONSTRAINT history_key_epochs_pkey PRIMARY KEY (id),
    CONSTRAINT history_key_epochs_ksf_lanes_check CHECK ((ksf_lanes > 0)),
    CONSTRAINT history_key_epochs_ksf_memory_kib_check CHECK ((ksf_memory_kib > 0)),
    CONSTRAINT history_key_epochs_ksf_passes_check CHECK ((ksf_passes > 0)),
    CONSTRAINT history_key_epochs_ksf_salt_check CHECK ((octet_length(ksf_salt) = 32)),
    CONSTRAINT history_key_epochs_owner_domain_check CHECK ((octet_length(owner_domain) = 32)),
    CONSTRAINT history_key_epochs_public_key_check CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT history_key_epochs_status_check CHECK ((status = ANY (ARRAY['active'::text, 'compare_only'::text, 'retired'::text]))),
    CONSTRAINT history_key_epochs_suite_check CHECK ((suite = 'pallas-poseidon-v1'::text))
);

CREATE TABLE history_key_lifecycle (
    owner_domain bytea NOT NULL,
    revision bigint NOT NULL,
    live_epochs uuid[] NOT NULL,
    CONSTRAINT history_key_lifecycle_pkey PRIMARY KEY (owner_domain),
    CONSTRAINT history_key_lifecycle_owner_domain_check CHECK ((octet_length(owner_domain) = 32)),
    CONSTRAINT history_key_lifecycle_revision_check CHECK ((revision >= 0))
);

CREATE TABLE history_key_purged (
    owner_domain bytea NOT NULL,
    purged_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT history_key_purged_pkey PRIMARY KEY (owner_domain),
    CONSTRAINT history_key_purged_owner_domain_check CHECK ((octet_length(owner_domain) = 32))
);

CREATE TABLE history_key_replaced (
    epoch_id uuid NOT NULL,
    owner_domain bytea NOT NULL,
    replaced_at_revision bigint NOT NULL,
    CONSTRAINT history_key_replaced_pkey PRIMARY KEY (epoch_id),
    CONSTRAINT history_key_replaced_epoch_id_fkey FOREIGN KEY (epoch_id) REFERENCES history_key_epochs(id) ON DELETE CASCADE,
    CONSTRAINT history_key_replaced_owner_domain_check CHECK ((octet_length(owner_domain) = 32)),
    CONSTRAINT history_key_replaced_replaced_at_revision_check CHECK ((replaced_at_revision > 0))
);

CREATE TABLE history_key_uses (
    operation_id uuid NOT NULL,
    epoch_id uuid NOT NULL,
    owner_domain bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT history_key_uses_pkey PRIMARY KEY (operation_id, epoch_id),
    CONSTRAINT history_key_uses_epoch_id_fkey FOREIGN KEY (epoch_id) REFERENCES history_key_epochs(id) ON DELETE CASCADE,
    CONSTRAINT history_key_uses_owner_domain_check CHECK ((octet_length(owner_domain) = 32))
);

CREATE TABLE history_key_versions (
    version integer NOT NULL,
    salt bytea NOT NULL,
    algorithm text NOT NULL,
    context text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT history_key_versions_pkey PRIMARY KEY (version),
    CONSTRAINT history_key_versions_version_check CHECK ((version > 0))
);

CREATE TABLE history_key_write_cutoff (
    singleton boolean DEFAULT true NOT NULL,
    not_before timestamp with time zone,
    CONSTRAINT history_key_write_cutoff_pkey PRIMARY KEY (singleton),
    CONSTRAINT history_key_write_cutoff_singleton_check CHECK (singleton)
);

CREATE INDEX history_key_epochs_created_by ON history_key_epochs USING btree (created_by) WHERE (created_by IS NOT NULL);

CREATE INDEX history_key_epochs_owner ON history_key_epochs USING btree (owner_domain);

CREATE UNIQUE INDEX history_key_one_active_epoch ON history_key_epochs USING btree (owner_domain) WHERE (status = 'active'::text);

CREATE INDEX history_key_uses_owner ON history_key_uses USING btree (owner_domain, epoch_id);

INSERT INTO history_key_write_cutoff (singleton) VALUES (TRUE);
