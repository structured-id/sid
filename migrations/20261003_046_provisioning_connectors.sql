-- Provisioning connectors: one directory source or target acting as its own
-- non-human actor, with credentials stored only as verifiers. org_id is not
-- a foreign key: in a tenant runtime the organizations live outside this
-- schema, as for oauth2_clients.org_id.
CREATE TABLE IF NOT EXISTS provisioning_connectors (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    display_name TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'disabled', 'retired')),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_provisioning_connectors_org
    ON provisioning_connectors (org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS provisioning_credentials (
    id UUID PRIMARY KEY,
    connector_id UUID NOT NULL REFERENCES provisioning_connectors (id),
    status TEXT NOT NULL CHECK (status IN ('active', 'grace_period', 'expired', 'revoked')),
    -- SHA-256 of the secret: the lookup key, unique across connectors.
    verifier TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_provisioning_credentials_connector
    ON provisioning_credentials (connector_id, created_at DESC);
