-- Principal assignment: one explicit assignment routes login; claims never do.
--
-- `owner_profile_id` becomes the assignment. `assignment_revision` counts its
-- generations: 0 only for a principal that was never used, so first use
-- cannot reopen after a release.

ALTER TABLE principals RENAME COLUMN owner_profile_id TO assigned_profile_id;
ALTER INDEX idx_principals_owner_profile_id RENAME TO idx_principals_assigned_profile_id;
ALTER TABLE principals ADD COLUMN assignment_revision BIGINT NOT NULL DEFAULT 0;

-- An expired proof used to clear the owner. A sole claimant was routed
-- regardless, so it takes the assignment it effectively held.
UPDATE principals p
SET assigned_profile_id = b.subject_id
FROM principal_bindings b
WHERE p.assigned_profile_id IS NULL
  AND b.principal_id = p.id
  AND b.subject_type = 'profile'
  AND (SELECT COUNT(*) FROM principal_bindings c WHERE c.principal_id = p.id) = 1;

-- An owner that no longer claims the principal holds no route.
UPDATE principals p
SET assigned_profile_id = NULL
WHERE p.assigned_profile_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM principal_bindings b
      WHERE b.principal_id = p.id
        AND b.subject_type = 'profile'
        AND b.subject_id = p.assigned_profile_id
  );

-- Pre-principal corporate logins were stored as 'custom'; they are usernames.
UPDATE principals p
SET principal_type = 'username'
WHERE p.principal_type = 'custom'
  AND NOT EXISTS (
      SELECT 1 FROM principals u
      WHERE u.principal_type = 'username' AND u.value = p.value
  );

-- Every existing principal has been used.
UPDATE principals SET assignment_revision = 1;
