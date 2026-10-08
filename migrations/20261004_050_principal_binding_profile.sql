-- A principal binding is a Profile's claim: it names that Profile directly.

DELETE FROM principal_bindings WHERE subject_type <> 'profile';

ALTER TABLE principal_bindings DROP CONSTRAINT uq_principal_binding;
ALTER TABLE principal_bindings DROP CONSTRAINT chk_binding_subject_type;
DROP INDEX IF EXISTS idx_principal_bindings_subject;

ALTER TABLE principal_bindings DROP COLUMN subject_type;
ALTER TABLE principal_bindings RENAME COLUMN subject_id TO profile_id;

ALTER TABLE principal_bindings
    ADD CONSTRAINT uq_principal_binding UNIQUE (principal_id, profile_id);
CREATE INDEX idx_principal_bindings_profile ON principal_bindings(profile_id);
