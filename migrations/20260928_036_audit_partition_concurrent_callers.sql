-- Two callers creating the same month at once (replicas running partition
-- maintenance together) both passed the existence check and the second
-- CREATE failed with duplicate_table. A transaction-scoped advisory lock on
-- this schema's partition name makes the check and the creation one step;
-- the lock is released when the caller's transaction ends.
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

    PERFORM pg_advisory_xact_lock(
        hashtextextended(current_schema() || '.' || partition_name, 0));

    IF to_regclass(partition_name) IS NOT NULL THEN
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
