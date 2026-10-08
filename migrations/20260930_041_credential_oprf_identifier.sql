-- Every password credential gets its own OPAQUE credential identifier
-- (RFC 9807 §5), and so its own OPRF key: the key of a new password has
-- evaluated nothing but that password's own registration request before the
-- record is committed, so the record can only enroll the password the
-- registration proof was made for. Passwords installed before this column
-- keep the identifier their logins always used, the profile id.
ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS opaque_credential_identifier BYTEA
        CHECK (octet_length(opaque_credential_identifier) = 16);

UPDATE credentials
SET opaque_credential_identifier = uuid_send(profile_id)
WHERE credential_type = 'opaque' AND opaque_credential_identifier IS NULL;
