-- Migration: Rename identifiers → principals (task #695)
-- Part of P1-REFACTOR: Identifier → Principal terminology alignment
--
-- Changes:
--   1. Rename table identifiers → principals
--   2. Rename column identifier_type → principal_type
--   3. Drop column login_enabled (always true for Principals by design)
--   4. Add column source_field (sync reference to Profile field, e.g., "email")
--   5. Rename table identifier_quarantine → principal_quarantine
--   6. Rename column identifier_quarantine.identifier_type → principal_type
--   7. Rename column identifier_quarantine.identifier_hash → principal_hash
--   8. Rename all indexes

-- Step 1: Rename identifiers table
ALTER TABLE identifiers RENAME TO principals;

-- Step 2: Rename column identifier_type → principal_type
ALTER TABLE principals RENAME COLUMN identifier_type TO principal_type;

-- Step 3: Drop login_enabled (always true, not used in domain model)
ALTER TABLE principals DROP COLUMN login_enabled;

-- Step 4: Add source_field column (nullable — NULL means Person-level or not bound to profile field)
ALTER TABLE principals ADD COLUMN source_field TEXT;

-- Step 5: Rename indexes on principals table
ALTER INDEX idx_identifiers_type_value RENAME TO idx_principals_type_value;
ALTER INDEX idx_identifiers_profile_id RENAME TO idx_principals_profile_id;
ALTER INDEX idx_identifiers_value RENAME TO idx_principals_value;

-- Step 6: Rename identifier_quarantine table
ALTER TABLE identifier_quarantine RENAME TO principal_quarantine;

-- Step 7: Rename columns in quarantine table
ALTER TABLE principal_quarantine RENAME COLUMN identifier_hash TO principal_hash;
ALTER TABLE principal_quarantine RENAME COLUMN identifier_type TO principal_type;

-- Step 8: Rename quarantine index
ALTER INDEX idx_quarantine_until RENAME TO idx_principal_quarantine_until;
