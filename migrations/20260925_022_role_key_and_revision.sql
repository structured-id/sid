-- A role key is what role checks and separation-of-duty rules match on, so two
-- roles of one project may not share it. Existing keys were copied from the
-- names, which are already unique per project.
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_project_id_key_key;
ALTER TABLE roles ADD CONSTRAINT roles_project_id_key_key UNIQUE (project_id, key);

-- An update applies over the revision it was read at and moves it on.
ALTER TABLE roles ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0
    CHECK (revision >= 0);
