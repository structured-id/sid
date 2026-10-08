-- Migration: Add PrincipalSubject columns (task #694)
-- Adds subject_type + person_id to support PrincipalSubject::Person (SaaS).
-- CE/EE: profile_id is always set, subject_type = 'profile', person_id = NULL.

-- Step 1: Make profile_id nullable (Person-level principals have no profile_id)
ALTER TABLE principals ALTER COLUMN profile_id DROP NOT NULL;

-- Step 2: Add person_id column (nullable — only set for Person-level principals)
ALTER TABLE principals ADD COLUMN person_id UUID;

-- Step 3: Add subject_type column (discriminator for PrincipalSubject enum)
ALTER TABLE principals ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'profile';

-- Step 4: Constraint — exactly one of profile_id/person_id must be set, never both
ALTER TABLE principals ADD CONSTRAINT chk_principal_subject CHECK (
    (subject_type = 'profile' AND profile_id IS NOT NULL AND person_id IS NULL) OR
    (subject_type = 'person' AND person_id IS NOT NULL AND profile_id IS NULL)
);

-- Step 5: Index for Person-level principal lookup (SaaS login resolution)
CREATE INDEX idx_principals_person_id ON principals(person_id) WHERE person_id IS NOT NULL;
