-- WebAuthn user handles: the
-- opaque `user.id` of a Profile at one relying party, created once at its
-- first enrollment there and kept for all its passkeys. A discoverable
-- assertion names its account only through this association.
CREATE TABLE IF NOT EXISTS webauthn_user_handles (
    profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    rp_id       TEXT NOT NULL,
    user_handle BYTEA NOT NULL CHECK (octet_length(user_handle) = 16),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, rp_id),
    UNIQUE (rp_id, user_handle)
);
