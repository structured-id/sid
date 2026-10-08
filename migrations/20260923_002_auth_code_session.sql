-- The session an authorization code was redeemed into. A second use of the
-- code is refused and this session (with its tokens) is revoked
-- (RFC 6749 §4.1.2).
ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS session_id UUID;
