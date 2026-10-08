-- A profile update applies over the revision it was read at and moves it on,
-- so a stale copy never writes back a status, role or name changed since.
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0
    CHECK (revision >= 0);
