-- Profile listing pages in one total order (creation time, then id); the
-- index serves that order, replacing the creation-time-only one.
DROP INDEX IF EXISTS idx_profiles_created_at;
CREATE INDEX IF NOT EXISTS idx_profiles_created_id ON profiles (created_at, id);
