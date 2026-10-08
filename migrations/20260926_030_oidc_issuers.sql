-- Logical OIDC issuers: one per issuing authority and recipient organization.
-- A handle and a canonical URL belong to one issuer forever; rows are never
-- deleted, so neither can be given to another issuer.
CREATE TABLE IF NOT EXISTS oidc_issuers (
    id UUID PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    canonical_url TEXT NOT NULL UNIQUE,
    authority TEXT NOT NULL CHECK (authority IN ('local')),
    recipient_org UUID NOT NULL REFERENCES organizations(id),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (authority, recipient_org)
);

-- Token-signing keys of an issuer, one row per generation. The private key is
-- stored only sealed under the key manager.
CREATE TABLE IF NOT EXISTS oidc_issuer_signing_keys (
    issuer_id UUID NOT NULL REFERENCES oidc_issuers(id),
    generation INTEGER NOT NULL CHECK (generation >= 1),
    key_id TEXT NOT NULL,
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    sealed_private_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (issuer_id, generation)
);
