-- A Profile's pairwise identity at one organization (scope). The binding id
-- is the pairwise `sub` every client of that scope receives; it is allocated
-- on the first visit and never changes.
CREATE TABLE IF NOT EXISTS service_bindings (
    binding_id UUID PRIMARY KEY,
    profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    scope TEXT NOT NULL CHECK (btrim(scope) <> ''),
    -- Last index of the binding's HD derivation path, one per binding of a profile.
    binding_index INTEGER NOT NULL CHECK (binding_index >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (profile_id, scope),
    UNIQUE (profile_id, binding_index)
);
