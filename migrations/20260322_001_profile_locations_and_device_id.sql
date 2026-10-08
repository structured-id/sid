-- Profile login locations for designated location tracking.
-- Enables impossible travel suppression between known locations (roaming scenario).

CREATE TABLE IF NOT EXISTS profile_locations (
    profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    country     VARCHAR(2) NOT NULL,
    latitude    DOUBLE PRECISION NOT NULL,
    longitude   DOUBLE PRECISION NOT NULL,
    login_count INTEGER NOT NULL DEFAULT 1,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    designated  BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (profile_id, country)
);

CREATE INDEX IF NOT EXISTS idx_profile_locations_designated
    ON profile_locations (profile_id) WHERE designated = TRUE;

-- Add device_id index on sessions for new_device detection.
-- Session.device_id already exists as nullable UUID column.
-- We need an index for has_recent_session_from_device queries.
CREATE INDEX IF NOT EXISTS idx_sessions_device_lookup
    ON sessions (profile_id, device_id, created_at DESC)
    WHERE device_id IS NOT NULL;
