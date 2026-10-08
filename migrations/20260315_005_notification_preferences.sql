-- Notification delivery preferences (#526)
-- Per-profile opt-out/channel selection. Stored as JSONB for flexibility.
-- Security alerts are mandatory — enforced in application logic, not schema.

CREATE TABLE IF NOT EXISTS notification_preferences (
    profile_id  UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    preferences JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
