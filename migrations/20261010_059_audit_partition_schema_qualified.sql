-- The existence check resolved the bare partition name through the search
-- path, so a schema whose search path continues to public found public's
-- partition for the month and created none of its own. The check, the
-- partition and its parent are now named in this schema explicitly.
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
