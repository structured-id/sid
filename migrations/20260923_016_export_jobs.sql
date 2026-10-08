-- Data export jobs of a profile (GDPR Art. 20 portability): preparation state,
-- the archive once ready, and its download window.

CREATE TABLE IF NOT EXISTS export_jobs (
    id              UUID PRIMARY KEY,
    profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    format          TEXT NOT NULL CHECK (format IN ('json')),
    status          TEXT NOT NULL
                    CHECK (status IN ('not_started', 'preparing', 'ready', 'downloaded', 'expired')),
    archive_path    TEXT,
    size_bytes      BIGINT CHECK (size_bytes IS NULL OR size_bytes >= 0),
    checksum_sha256 TEXT,
    created_at      TIMESTAMPTZ NOT NULL,
    ready_at        TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_export_jobs_profile_created
    ON export_jobs (profile_id, created_at DESC);
