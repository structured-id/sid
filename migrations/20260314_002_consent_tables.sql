-- Consent CRUD storage (#506)
-- Consent records: per-(profile, client) claim grants with lifecycle tracking.

CREATE TABLE IF NOT EXISTS consents (
    id          UUID PRIMARY KEY,
    profile_id  UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'requested'
                    CHECK (status IN ('requested', 'active', 'revoked', 'expired')),
    consented_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (profile_id, client_id)
);

CREATE INDEX idx_consents_profile ON consents(profile_id);
CREATE INDEX idx_consents_client ON consents(client_id);

CREATE TABLE IF NOT EXISTS claim_grants (
    id          UUID PRIMARY KEY,
    consent_id  UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    claim_name  TEXT NOT NULL,
    claim_type  TEXT NOT NULL DEFAULT 'data'
                    CHECK (claim_type IN ('data', 'attestation')),
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ,
    UNIQUE (consent_id, claim_name)
);

CREATE INDEX idx_claim_grants_consent ON claim_grants(consent_id);
