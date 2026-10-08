-- Every application grant is for one protected resource (RFC 8707): the
-- authorization code, the refresh token and the device code carry the
-- resource their tokens are issued for, and redemption or refresh cannot
-- substitute another.
--
-- Grants issued before resources existed have no target; under the resource
-- model their audience is undefined, so they end here and the client signs
-- in again.
DELETE FROM authorization_codes;
DELETE FROM refresh_tokens;
DELETE FROM device_authorization_codes;

ALTER TABLE authorization_codes
    ADD COLUMN resource_id UUID NOT NULL REFERENCES protected_resources(id);
ALTER TABLE refresh_tokens
    ADD COLUMN resource_id UUID NOT NULL REFERENCES protected_resources(id);
ALTER TABLE device_authorization_codes
    ADD COLUMN resource_id UUID NOT NULL REFERENCES protected_resources(id);
