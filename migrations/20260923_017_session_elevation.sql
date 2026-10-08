-- A step-up to elevated/critical is time-bound: it lives beside the session's
-- own level and lapses at elevation_until.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS elevation_level TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS elevation_until TIMESTAMPTZ;

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_elevation_complete;
ALTER TABLE sessions ADD CONSTRAINT sessions_elevation_complete CHECK (
    (elevation_level IS NULL AND elevation_until IS NULL)
    OR (elevation_level IN ('elevated', 'critical') AND elevation_until IS NOT NULL)
);

-- Sessions stored as elevated/critical before this held the step-up for the
-- whole session. Their true base level is not recorded, so they drop to
-- basic; the next sensitive operation asks for a step-up again.
UPDATE sessions SET assurance_level = 'basic'
WHERE assurance_level IN ('elevated', 'critical');

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_base_assurance;
ALTER TABLE sessions ADD CONSTRAINT sessions_base_assurance
    CHECK (assurance_level IN ('basic', 'standard'));
