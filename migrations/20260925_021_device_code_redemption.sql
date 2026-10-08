-- Poll time for slow_down (RFC 8628 §3.5), read and written by the service
-- but missing from the table, so no device authorization could be stored.
ALTER TABLE device_authorization_codes ADD COLUMN IF NOT EXISTS last_polled_at TIMESTAMPTZ;

-- A device code is redeemed once; the session it produced is kept so that a
-- second redemption can end it.
ALTER TABLE device_authorization_codes
    ADD COLUMN IF NOT EXISTS redeemed_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL;

-- User codes are stored normalized (no separator), as they are looked up.
UPDATE device_authorization_codes SET user_code = replace(user_code, '-', '');

ALTER TABLE device_authorization_codes DROP CONSTRAINT IF EXISTS device_authorization_codes_status_known;
ALTER TABLE device_authorization_codes ADD CONSTRAINT device_authorization_codes_status_known
    CHECK (status IN ('pending', 'authorized', 'denied', 'expired', 'redeemed'));
