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

-- Open work only: what workers scan and what admission counts.
CREATE INDEX IF NOT EXISTS idx_durable_work_open
    ON durable_work (kind, not_before)
    WHERE state IN ('pending', 'claimed');
