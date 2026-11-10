-- Audit chains of a host keeping its own tables in its own database; the
-- engine's schema holds the same tables. Records are append-only and held in
-- monthly partitions, which the host prepares ahead and removes whole past
-- retention, leaving each chain a checkpoint.

-- The digest of the schema that made these tables; tables of another schema
-- are refused, not kept.
CREATE TABLE IF NOT EXISTS audit_schema (
    id boolean DEFAULT true NOT NULL,
    digest bytea NOT NULL,
    CONSTRAINT audit_schema_pkey PRIMARY KEY (id),
    CONSTRAINT audit_schema_id_check CHECK (id)
);

CREATE OR REPLACE FUNCTION audit_records_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'audit_records is append-only: % operations are forbidden', TG_OP;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION create_audit_partition(year integer, month integer) RETURNS text
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

CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
    chain_id text NOT NULL,
    sequence bigint NOT NULL,
    hash text NOT NULL,
    cut_before timestamp with time zone NOT NULL,
    CONSTRAINT audit_chain_checkpoints_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT audit_chain_checkpoints_pkey PRIMARY KEY (chain_id)
);

CREATE TABLE IF NOT EXISTS audit_chain_heads (
    chain_id text NOT NULL,
    last_record_id text NOT NULL,
    last_hash text NOT NULL,
    sequence bigint NOT NULL,
    CONSTRAINT audit_chain_heads_pkey PRIMARY KEY (chain_id)
);

CREATE TABLE IF NOT EXISTS audit_records (
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

CREATE TABLE IF NOT EXISTS audit_records_default PARTITION OF audit_records DEFAULT;

-- Each index and trigger is made only when the catalog lacks it: `CREATE
-- INDEX IF NOT EXISTS` locks its table before it finds the index, so a host
-- starting on a current schema would wait on the records its serving
-- replicas append, and they on it.
DO $$
BEGIN
    IF to_regclass('idx_audit_action') IS NULL THEN
        CREATE INDEX idx_audit_action ON audit_records USING btree (action);
    END IF;
    IF to_regclass('idx_audit_actor') IS NULL THEN
        CREATE INDEX idx_audit_actor ON audit_records USING btree (actor_id);
    END IF;
    IF to_regclass('idx_audit_chain_id') IS NULL THEN
        CREATE INDEX idx_audit_chain_id ON audit_records USING btree (chain_id, sequence);
    END IF;
    IF to_regclass('idx_audit_timestamp') IS NULL THEN
        CREATE INDEX idx_audit_timestamp ON audit_records USING btree ("timestamp");
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgname = 'trg_audit_records_no_delete'
                     AND tgrelid = 'audit_records'::regclass) THEN
        CREATE TRIGGER trg_audit_records_no_delete BEFORE DELETE ON audit_records
            FOR EACH ROW EXECUTE FUNCTION audit_records_immutable();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgname = 'trg_audit_records_no_update'
                     AND tgrelid = 'audit_records'::regclass) THEN
        CREATE TRIGGER trg_audit_records_no_update BEFORE UPDATE ON audit_records
            FOR EACH ROW EXECUTE FUNCTION audit_records_immutable();
    END IF;
END
$$;
