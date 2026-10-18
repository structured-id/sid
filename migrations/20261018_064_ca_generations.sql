-- CA key generations and their lifecycle (sid_plugin::CaRegistry).
-- A generation is prepared, certified, recovery-confirmed, then the one
-- current generation of its scope; only the current one allocates serials.
-- Private keys are never stored here in the clear: a key is either sealed by
-- the installation's key custody or named by an external signer's handle.
CREATE TABLE ca_generations (
    id                     UUID PRIMARY KEY,
    -- 'deployment' or 'organization'; the organization when the latter.
    scope_kind             TEXT NOT NULL CHECK (scope_kind IN ('deployment', 'organization')),
    scope_org              UUID,
    generation             INTEGER NOT NULL CHECK (generation > 0),
    classical_sealed       BYTEA,
    classical_external     TEXT,
    alternative_sealed     BYTEA,
    alternative_external   TEXT,
    certificate            BYTEA,
    database_recovery_ref  TEXT,
    database_recovery_by   TEXT,
    database_recovery_at   TIMESTAMPTZ,
    key_recovery_ref       TEXT,
    key_recovery_by        TEXT,
    key_recovery_at        TIMESTAMPTZ,
    state                  TEXT NOT NULL CHECK (state IN ('prepared', 'current', 'retired', 'revoked')),
    revision               BIGINT NOT NULL CHECK (revision > 0),
    last_serial            BIGINT NOT NULL DEFAULT 0 CHECK (last_serial >= 0),
    prepared_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((scope_kind = 'deployment') = (scope_org IS NULL)),
    -- Exactly one form of each key.
    CHECK ((classical_sealed IS NULL) <> (classical_external IS NULL)),
    CHECK (NOT (alternative_sealed IS NOT NULL AND alternative_external IS NOT NULL))
);

-- Generation numbers are unique within a scope.
CREATE UNIQUE INDEX ca_generations_scope_generation
    ON ca_generations (scope_kind, COALESCE(scope_org, '00000000-0000-0000-0000-000000000000'::uuid), generation);

-- At most one current generation per scope.
CREATE UNIQUE INDEX ca_generations_one_current
    ON ca_generations (scope_kind, COALESCE(scope_org, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE state = 'current';
