-- An invite is created by an administrator Profile or by a machine user
-- holding the invite action on the enrollment API: exactly one is named.
ALTER TABLE invites ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE invites ADD COLUMN created_by_machine UUID REFERENCES machine_users(id);
ALTER TABLE invites ADD CONSTRAINT invites_one_creator
    CHECK ((created_by IS NULL) <> (created_by_machine IS NULL));

-- The registrations that used an invite: the Profile each created, written
-- in the registration's own transaction together with the use.
CREATE TABLE IF NOT EXISTS invite_redemptions (
    invite_id   UUID NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    redeemed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (invite_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_invite_redemptions_order
    ON invite_redemptions (invite_id, redeemed_at, profile_id);
