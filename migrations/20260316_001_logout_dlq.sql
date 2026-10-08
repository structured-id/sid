-- Back-channel logout dead-letter queue.
-- Failed OIDC back-channel logout notifications stored for admin review and manual retry.
CREATE TABLE IF NOT EXISTS logout_dlq (
    id                UUID PRIMARY KEY,
    client_id         TEXT NOT NULL,
    logout_uri        TEXT NOT NULL,
    profile_id        TEXT NOT NULL,
    session_id        TEXT,
    attempts          INTEGER NOT NULL DEFAULT 1,
    last_error        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_logout_dlq_client
    ON logout_dlq(client_id);

CREATE INDEX IF NOT EXISTS idx_logout_dlq_created
    ON logout_dlq(created_at);
