-- A connector's OAuth client_id (its protocol name at the token endpoint,
-- distinct from its ID) and the kind of each credential: a SCIM bearer or an
-- OAuth client secret, never accepted for the other.
ALTER TABLE provisioning_connectors ADD COLUMN IF NOT EXISTS client_id TEXT;
UPDATE provisioning_connectors
    SET client_id = 'pc_' || replace(gen_random_uuid()::text, '-', '')
    WHERE client_id IS NULL;
ALTER TABLE provisioning_connectors ALTER COLUMN client_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_provisioning_connectors_client_id
    ON provisioning_connectors (client_id);

ALTER TABLE provisioning_credentials ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL
    DEFAULT 'scim_bearer' CHECK (kind IN ('scim_bearer', 'client_secret'));
ALTER TABLE provisioning_credentials ALTER COLUMN kind DROP DEFAULT;
