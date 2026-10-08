-- A month's partition exists when this schema has it: the name resolves
-- through the search path, the same one CREATE TABLE below uses. A bare
-- pg_class name match also saw another installation's schema in the same
-- database and left this one without the partition.
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
