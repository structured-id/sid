-- Ordinary tokens carry the recipient's subject only: moving an application's
-- users to another identifier is a dedicated continuity flow, not a timed
-- second `sub` keyed by when the client's subject type changed.
ALTER TABLE oauth2_clients DROP COLUMN IF EXISTS subject_type_changed_at;
