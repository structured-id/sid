-- The credential an invite registration installed, beside the Profile it
-- created: the client that ran the registration recognizes its own
-- redemption by it. Empty for a registration that installed none.
ALTER TABLE invite_redemptions
    ADD COLUMN IF NOT EXISTS credential_id UUID REFERENCES credentials(id) ON DELETE SET NULL;
