-- Principal Contestation Model: Independent Entity + Bindings
--
-- Transforms the principals table from "one row per profile" into
-- "one entity per (type, value)" with M:N bindings to subjects.
--
-- See: arch/identity/identity-model.md §Principal Verification & Contestation Model

-- Step 1: Create principal_bindings table (M:N relationship)
CREATE TABLE principal_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id    UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    subject_type    TEXT NOT NULL,                    -- 'profile' or 'person'
    subject_id      UUID NOT NULL,                    -- ProfileId or PersonId
    is_primary      BOOLEAN NOT NULL DEFAULT FALSE,
    source_field    TEXT,                              -- "email", "phone"
    source_email_id UUID,                             -- FK to profile_emails
    source_phone_id UUID,                             -- FK to profile_phones
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One binding per (principal, subject) pair
    CONSTRAINT uq_principal_binding UNIQUE (principal_id, subject_type, subject_id),
    -- Subject type must be valid
    CONSTRAINT chk_binding_subject_type CHECK (subject_type IN ('profile', 'person'))
);

CREATE INDEX idx_principal_bindings_principal_id ON principal_bindings(principal_id);
CREATE INDEX idx_principal_bindings_subject ON principal_bindings(subject_type, subject_id);

-- Step 2: Migrate existing data from principals to bindings
INSERT INTO principal_bindings (id, principal_id, subject_type, subject_id, is_primary, source_field, source_email_id, source_phone_id, created_at)
SELECT
    gen_random_uuid(),
    id,
    subject_type,
    COALESCE(profile_id, person_id),
    is_primary,
    source_field,
    source_email_id,
    source_phone_id,
    created_at
FROM principals
WHERE (profile_id IS NOT NULL OR person_id IS NOT NULL);

-- Step 3: Add owner_profile_id to principals entity
ALTER TABLE principals ADD COLUMN owner_profile_id UUID;

-- Set owner for verified principals
UPDATE principals SET owner_profile_id = profile_id
WHERE verified = true AND profile_id IS NOT NULL;

-- Step 4: Drop moved columns from principals
-- These now live in principal_bindings
ALTER TABLE principals DROP COLUMN IF EXISTS profile_id;
ALTER TABLE principals DROP COLUMN IF EXISTS person_id;
ALTER TABLE principals DROP COLUMN IF EXISTS subject_type;
ALTER TABLE principals DROP COLUMN IF EXISTS is_primary;
ALTER TABLE principals DROP COLUMN IF EXISTS source_field;
ALTER TABLE principals DROP COLUMN IF EXISTS source_email_id;
ALTER TABLE principals DROP COLUMN IF EXISTS source_phone_id;

-- Drop the old check constraint (references dropped columns)
ALTER TABLE principals DROP CONSTRAINT IF EXISTS chk_principal_subject;

-- Drop old indexes that referenced dropped columns
DROP INDEX IF EXISTS idx_principals_profile_id;
DROP INDEX IF EXISTS idx_principals_person_id;

-- Step 5: The UNIQUE index on (principal_type, value) stays —
-- it enforces one entity per identifier. This is correct.
-- idx_principals_type_value already exists.

-- Step 6: Add index on owner_profile_id for eligibility lookups
CREATE INDEX idx_principals_owner_profile_id ON principals(owner_profile_id)
WHERE owner_profile_id IS NOT NULL;
