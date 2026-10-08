-- Add subject_type_changed_at to oauth2_clients for Public→Pairwise dual-sub transition.
-- During the 90-day transition period, tokens include both `sub` (new pairwise)
-- and `sid_legacy_sub` (old public ProfileId).
ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS subject_type_changed_at TIMESTAMPTZ;
