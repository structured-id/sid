-- Keyed command completions and the periods they are admitted under, for a
-- host keeping its own tables in its own database; the engine's schema holds
-- the same tables.
CREATE TABLE IF NOT EXISTS operation_period_state (
    id boolean DEFAULT true NOT NULL,
    issued_through bigint DEFAULT 0 NOT NULL,
    acceptance_seconds bigint DEFAULT 3600 NOT NULL,
    retention_seconds bigint DEFAULT 86400 NOT NULL,
    -- Completions one period holds, and the largest result one keeps.
    capacity bigint DEFAULT 100000 NOT NULL,
    result_bytes bigint DEFAULT 65536 NOT NULL,
    CONSTRAINT operation_period_state_pkey PRIMARY KEY (id),
    CONSTRAINT operation_period_state_id_check CHECK (id),
    CONSTRAINT operation_period_state_issued_through_check CHECK (issued_through >= 0),
    CONSTRAINT operation_period_state_acceptance_check CHECK (acceptance_seconds > 0),
    CONSTRAINT operation_period_state_retention_check CHECK (retention_seconds >= 0),
    CONSTRAINT operation_period_state_capacity_check CHECK (capacity > 0),
    CONSTRAINT operation_period_state_result_bytes_check CHECK (result_bytes > 0)
);

INSERT INTO operation_period_state (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS operation_periods (
    period bigint NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    accepted_until timestamp with time zone NOT NULL,
    -- Completions committed under the period.
    recorded bigint DEFAULT 0 NOT NULL,
    CONSTRAINT operation_periods_pkey PRIMARY KEY (period),
    CONSTRAINT operation_periods_period_check CHECK (period > 0),
    CONSTRAINT operation_periods_recorded_check CHECK (recorded >= 0)
);

CREATE TABLE IF NOT EXISTS operation_results (
    namespace text NOT NULL,
    op_key text NOT NULL,
    method text NOT NULL,
    fingerprint bytea NOT NULL,
    result bytea NOT NULL,
    completed_at timestamp with time zone DEFAULT now() NOT NULL,
    period bigint,
    retain_until timestamp with time zone,
    CONSTRAINT operation_results_pkey PRIMARY KEY (namespace, op_key),
    CONSTRAINT operation_results_period_fkey FOREIGN KEY (period) REFERENCES operation_periods(period)
);

-- Each index is made only when the catalog lacks it: `CREATE INDEX IF NOT
-- EXISTS` locks its table before it finds the index, so a host starting on a
-- current schema would wait on the completions its serving replicas write,
-- and they on it.
DO $$
BEGIN
    IF to_regclass('operation_results_retain_until') IS NULL THEN
        CREATE INDEX operation_results_retain_until
            ON operation_results USING btree (retain_until) WHERE (retain_until IS NOT NULL);
    END IF;
    -- A retirement drops a period's completions by it.
    IF to_regclass('operation_results_period') IS NULL THEN
        CREATE INDEX operation_results_period
            ON operation_results USING btree (period) WHERE (period IS NOT NULL);
    END IF;
END
$$;

-- The identifier each keyed creation allocated, bound to its command. No key
-- to operation_periods: a binding of a creation that never completed outlives
-- the retirement of its period, kept to reconcile what it began.
CREATE TABLE IF NOT EXISTS operation_resources (
    namespace text NOT NULL,
    op_key text NOT NULL,
    method text NOT NULL,
    fingerprint bytea NOT NULL,
    period bigint,
    resource uuid NOT NULL,
    bound_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT operation_resources_pkey PRIMARY KEY (namespace, op_key)
);

DO $$
BEGIN
    IF to_regclass('operation_resources_period') IS NULL THEN
        CREATE INDEX operation_resources_period
            ON operation_resources USING btree (period) WHERE (period IS NOT NULL);
    END IF;
END
$$;
