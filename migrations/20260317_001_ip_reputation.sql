-- IP reputation tracking for SelfLearnedReputationProvider.
-- Tracks failed/successful login counts per IP with computed score.
-- Score = failed_count / (failed_count + success_count + 1.0)
-- IPs with score > threshold are classified as suspicious/blocklisted.

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip          TEXT PRIMARY KEY,
    failed_count    INTEGER NOT NULL DEFAULT 0,
    success_count   INTEGER NOT NULL DEFAULT 0,
    score           REAL NOT NULL DEFAULT 0.0,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at  TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient refresh query (suspicious IPs only).
CREATE INDEX IF NOT EXISTS idx_ip_reputation_score
    ON ip_reputation (score DESC)
    WHERE score > 0.3;

-- Index for cleanup of stale entries.
CREATE INDEX IF NOT EXISTS idx_ip_reputation_updated
    ON ip_reputation (updated_at);
