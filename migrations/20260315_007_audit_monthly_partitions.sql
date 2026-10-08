-- Convert audit_records from regular table to monthly-partitioned table.
-- Enables efficient retention management: DROP PARTITION vs DELETE.
--
-- PostgreSQL partitioned tables require:
--   1. Partition key (timestamp) in PRIMARY KEY
--   2. All UNIQUE constraints must include partition key

-- Step 1: Drop triggers and indexes (will be re-created on partitioned table)
DROP TRIGGER IF EXISTS trg_audit_records_no_update ON audit_records;
DROP TRIGGER IF EXISTS trg_audit_records_no_delete ON audit_records;
DROP INDEX IF EXISTS idx_audit_chain_id;
DROP INDEX IF EXISTS idx_audit_timestamp;
DROP INDEX IF EXISTS idx_audit_action;
DROP INDEX IF EXISTS idx_audit_actor;

-- Step 2: Rename old table (constraints go with it)
ALTER TABLE IF EXISTS audit_records RENAME TO audit_records_old;

-- Step 3: Create partitioned table (same columns, new PK includes timestamp)
CREATE TABLE audit_records (
    id          TEXT        NOT NULL,
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

    PRIMARY KEY (id, timestamp),
    CONSTRAINT uq_audit_chain_seq UNIQUE (chain_id, sequence, timestamp)
) PARTITION BY RANGE (timestamp);

-- Step 4: Create monthly partitions for 2026
CREATE TABLE audit_records_2026_01 PARTITION OF audit_records
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE audit_records_2026_02 PARTITION OF audit_records
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE audit_records_2026_03 PARTITION OF audit_records
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE audit_records_2026_04 PARTITION OF audit_records
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE audit_records_2026_05 PARTITION OF audit_records
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_records_2026_06 PARTITION OF audit_records
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE audit_records_2026_07 PARTITION OF audit_records
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE audit_records_2026_08 PARTITION OF audit_records
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE audit_records_2026_09 PARTITION OF audit_records
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE audit_records_2026_10 PARTITION OF audit_records
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE audit_records_2026_11 PARTITION OF audit_records
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE audit_records_2026_12 PARTITION OF audit_records
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

-- Default partition catches data outside defined ranges (safety net)
CREATE TABLE audit_records_default PARTITION OF audit_records DEFAULT;

-- Step 5: Migrate existing data (if any)
INSERT INTO audit_records SELECT * FROM audit_records_old;

-- Step 6: Drop old table
DROP TABLE audit_records_old;

-- Step 7: Re-create indexes on partitioned table
CREATE INDEX IF NOT EXISTS idx_audit_chain_id ON audit_records (chain_id, sequence);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_records (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_records (action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_records (actor_id);

-- Step 8: Re-create append-only triggers
CREATE TRIGGER trg_audit_records_no_update
    BEFORE UPDATE ON audit_records
    FOR EACH ROW EXECUTE FUNCTION audit_records_immutable();

CREATE TRIGGER trg_audit_records_no_delete
    BEFORE DELETE ON audit_records
    FOR EACH ROW EXECUTE FUNCTION audit_records_immutable();

-- Step 9: Function to create a monthly partition (for background task)
CREATE OR REPLACE FUNCTION create_audit_partition(year INT, month INT)
RETURNS TEXT
LANGUAGE plpgsql AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    partition_name := format('audit_records_%s_%s',
        year, lpad(month::TEXT, 2, '0'));
    start_date := make_date(year, month, 1);
    end_date := start_date + INTERVAL '1 month';

    -- Check if partition already exists
    IF EXISTS (
        SELECT 1 FROM pg_class WHERE relname = partition_name
    ) THEN
        RETURN partition_name || ' (already exists)';
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF audit_records
         FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date
    );

    RETURN partition_name || ' (created)';
END;
$$;
