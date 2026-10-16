-- The installation's enrollment policy (auth/enrollment-policy.md): who may
-- self-register. One row, written by an administrator; without it the
-- built-in defaults apply. A deployment may pin the mode, which then wins
-- over the stored one without being written here.
CREATE TABLE IF NOT EXISTS enrollment_policy (
    scope                       TEXT PRIMARY KEY CHECK (scope = 'installation'),
    mode                        TEXT NOT NULL
        CHECK (mode IN ('open', 'invite_only', 'admin_only', 'domain_restricted')),
    allowed_domains             TEXT[] NOT NULL DEFAULT '{}',
    track_source                BOOLEAN NOT NULL,
    invite_default_max_uses     BIGINT NOT NULL CHECK (invite_default_max_uses BETWEEN 0 AND 4294967295),
    invite_default_expiry_hours BIGINT NOT NULL CHECK (invite_default_expiry_hours BETWEEN 0 AND 4294967295),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
