-- A draft edit applies over the revision it was read at, so a stale copy
-- never overwrites a concurrent edit. The status column is the record's
-- status; the one inside `data` is not read.
ALTER TABLE branding_configs ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0
    CHECK (revision >= 0);
