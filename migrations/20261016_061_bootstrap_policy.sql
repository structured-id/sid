-- The installation's bootstrap policy (auth/enrollment-policy.md, First
-- Administrator). A row exists only once the installation is centrally
-- managed, and is never removed: no restart, restore of later data or
-- configuration reopens its local administrator claim. Without a row the
-- installation is self-managed.
CREATE TABLE IF NOT EXISTS bootstrap_policy (
    scope TEXT PRIMARY KEY CHECK (scope = 'installation'),
    policy TEXT NOT NULL CHECK (policy = 'centrally_managed'),
    adopted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A centrally managed installation stores no administrator claim. Enforced
-- here rather than only in the server, so a replica of a build that knows
-- nothing of the policy fails to open a claim instead of creating one it
-- could later consume.
CREATE OR REPLACE FUNCTION refuse_admin_claim_when_centrally_managed() RETURNS trigger AS $$
BEGIN
    IF NEW.name = 'admin_claim' AND EXISTS (SELECT 1 FROM bootstrap_policy) THEN
        RAISE EXCEPTION 'centrally managed installation: no administrator claim';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER instance_secrets_no_claim_when_centrally_managed
BEFORE INSERT OR UPDATE ON instance_secrets
FOR EACH ROW EXECUTE FUNCTION refuse_admin_claim_when_centrally_managed();
