-- Organizations. An installation holds exactly one organization of its own
-- (`is_instance`): the implicit Community organization of a CE installation,
-- created at first boot by whichever replica starts first.
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    org_type TEXT NOT NULL
        CHECK (org_type IN ('family', 'community', 'commercial', 'government')),
    status TEXT NOT NULL
        CHECK (status IN ('pending_dns', 'pending_claim', 'active_trial', 'active',
                          'suspended', 'deprovisioning', 'deleted')),
    canonical_domain TEXT NOT NULL,
    is_instance BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS organizations_one_instance
    ON organizations (is_instance) WHERE is_instance;

-- A client's organization is the grouping key of its pairwise subjects.
-- No code path assigned the column, so any value in it names no
-- organization; it is cleared, and start-up assigns the installation's.
ALTER TABLE oauth2_clients
    ALTER COLUMN org_id TYPE UUID USING NULL;
ALTER TABLE oauth2_clients
    DROP CONSTRAINT IF EXISTS oauth2_clients_org_id_fkey;
ALTER TABLE oauth2_clients
    ADD CONSTRAINT oauth2_clients_org_id_fkey
    FOREIGN KEY (org_id) REFERENCES organizations(id);
