-- Required work committed with the state change that needs it (transactional
-- outbox). Workers claim it under a lease; `generation` fences each outcome so
-- a worker whose lease expired cannot overwrite its successor's result.
CREATE TABLE IF NOT EXISTS durable_work (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL,
    payload BYTEA NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    generation BIGINT NOT NULL DEFAULT 0,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    -- The last failed attempt may have had its effect (reply lost).
    ambiguous BOOLEAN NOT NULL DEFAULT false,
    -- What completing the work produced, such as a provider receipt.
    result TEXT,
    not_before TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One index per question a claim asks, each read by kind and time: due
-- pending work, claimed work whose lease ran out, open work past its expiry.
CREATE INDEX IF NOT EXISTS idx_durable_work_due
    ON durable_work (kind, not_before)
    WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_durable_work_lease
    ON durable_work (kind, lease_until)
    WHERE state = 'claimed';
CREATE INDEX IF NOT EXISTS idx_durable_work_expiry
    ON durable_work (kind, expires_at)
    WHERE state IN ('pending', 'claimed') AND expires_at IS NOT NULL;

-- Open items per kind, which admission reads instead of counting rows. Split
-- into shards by the work's id, so completions of one kind do not all wait
-- on one counter row; admission sums the shards under its kind's lock.
CREATE TABLE IF NOT EXISTS durable_work_open (
    kind TEXT NOT NULL,
    shard SMALLINT NOT NULL,
    open BIGINT NOT NULL,
    PRIMARY KEY (kind, shard)
);

-- Kept by triggers on every write that opens or ends work, so no write path
-- can leave the count behind. A transaction that takes kinds' admission
-- locks takes them before any write firing these triggers, the order an
-- enqueue holds them: a shard held while waiting for a kind's lock would
-- deadlock with an enqueue holding that lock while waiting for the shard.
CREATE OR REPLACE FUNCTION durable_work_count_open() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' AND OLD.state IN ('pending', 'claimed') THEN
        INSERT INTO durable_work_open (kind, shard, open)
        VALUES (OLD.kind, get_byte(uuid_send(OLD.id), 15) % 16, -1)
        ON CONFLICT (kind, shard) DO UPDATE SET open = durable_work_open.open - 1;
    END IF;
    IF TG_OP <> 'DELETE' AND NEW.state IN ('pending', 'claimed') THEN
        INSERT INTO durable_work_open (kind, shard, open)
        VALUES (NEW.kind, get_byte(uuid_send(NEW.id), 15) % 16, 1)
        ON CONFLICT (kind, shard) DO UPDATE SET open = durable_work_open.open + 1;
    END IF;
    RETURN NULL;
END;
$$;

-- Only writes that change whether an item is open touch the count: a claim
-- or a retry keeps it open and fires nothing.
CREATE OR REPLACE TRIGGER durable_work_opened
    AFTER INSERT ON durable_work FOR EACH ROW
    WHEN (NEW.state IN ('pending', 'claimed'))
    EXECUTE FUNCTION durable_work_count_open();
CREATE OR REPLACE TRIGGER durable_work_open_changed
    AFTER UPDATE OF state ON durable_work FOR EACH ROW
    WHEN ((OLD.state IN ('pending', 'claimed')) <> (NEW.state IN ('pending', 'claimed')))
    EXECUTE FUNCTION durable_work_count_open();
CREATE OR REPLACE TRIGGER durable_work_closed
    AFTER DELETE ON durable_work FOR EACH ROW
    WHEN (OLD.state IN ('pending', 'claimed'))
    EXECUTE FUNCTION durable_work_count_open();
