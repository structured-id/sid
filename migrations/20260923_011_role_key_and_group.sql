-- A role's stable machine key (used in Cedar policies and token claims) and
-- its UI grouping label. Existing roles take their name as key.
ALTER TABLE roles ADD COLUMN IF NOT EXISTS key TEXT NOT NULL DEFAULT '';
ALTER TABLE roles ADD COLUMN IF NOT EXISTS group_label TEXT;
UPDATE roles SET key = name WHERE key = '';
