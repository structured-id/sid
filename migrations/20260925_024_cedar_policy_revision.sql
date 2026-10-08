-- A policy update applies over the revision it was read at and moves it on,
-- so a stale copy never re-enables a disabled policy or recreates a deleted one.
ALTER TABLE cedar_policies ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0
    CHECK (revision >= 0);
