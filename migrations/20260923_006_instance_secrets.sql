-- Secrets every replica of the instance shares (the OPAQUE server setup),
-- sealed by the field-encryption key manager. Written once by whichever
-- replica starts first and never replaced: stored password records depend on
-- them, so they live as long as the instance.
CREATE TABLE IF NOT EXISTS instance_secrets (
    name TEXT PRIMARY KEY,
    sealed BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
