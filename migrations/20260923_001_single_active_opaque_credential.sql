-- A profile has one password: at most one active OPAQUE credential.
--
-- A profile holding several active OPAQUE credentials could only get them through
-- self-registration attaching to an existing account. The owner's password cannot
-- be told apart from an added one, so every active OPAQUE credential of such a
-- profile is revoked; the owner regains access through password reset.
UPDATE credentials
SET status = 'revoked'
WHERE credential_type = 'opaque'
  AND status = 'active'
  AND profile_id IN (
      SELECT profile_id
      FROM credentials
      WHERE credential_type = 'opaque' AND status = 'active'
      GROUP BY profile_id
      HAVING COUNT(*) > 1
  );

CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_active_opaque
    ON credentials (profile_id)
    WHERE credential_type = 'opaque' AND status = 'active';
