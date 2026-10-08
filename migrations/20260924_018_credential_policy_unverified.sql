-- A credential registered without a verified policy proof stays
-- policy-unverified with no deadline: nothing later changes it and nothing
-- expires it, so the deadline column goes.
ALTER TABLE credentials DROP COLUMN IF EXISTS zk_verification_deadline;

-- Only the types and statuses the service reads are stored.
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_type_known;
ALTER TABLE credentials ADD CONSTRAINT credentials_type_known
    CHECK (credential_type IN ('opaque', 'webauthn', 'totp', 'recovery', 'legacy_hash'));
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_status_known;
ALTER TABLE credentials ADD CONSTRAINT credentials_status_known
    CHECK (status IN ('active', 'revoked'));
