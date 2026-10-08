-- Where a hash chain resumes after retention removed its oldest records: the
-- last removed record's sequence and hash, so the first remaining record
-- still verifies against it instead of reading as a broken link.
CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
    chain_id    TEXT        PRIMARY KEY,
    sequence    BIGINT      NOT NULL CHECK (sequence > 0),
    hash        TEXT        NOT NULL,
    cut_before  TIMESTAMPTZ NOT NULL
);
