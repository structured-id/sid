-- A client is updated only over the revision it was read at, so an update
-- racing a deletion or another update never restores what they changed.
ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE oauth2_clients DROP CONSTRAINT IF EXISTS oauth2_clients_revision_non_negative;
ALTER TABLE oauth2_clients ADD CONSTRAINT oauth2_clients_revision_non_negative
    CHECK (revision >= 0);
