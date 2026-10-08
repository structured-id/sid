-- Email policy revisions.
--
-- An email principal records the revision of the installation's email
-- policy its key was derived under. The installation's active revision
-- fences writers: a key written under any other revision, or by a build
-- that does not know revisions, is refused.
--
-- Keys written before revisions existed get revision 0: their provenance is
-- unknown (the old normalizer folded and confusable-mapped spellings, and
-- copied the folded key into the contact), and nothing stored establishes
-- the address they stand for. Each one is recorded as quarantined: it stays
-- reserved, so nobody else takes the handle, but routes no login and
-- receives no mail until its address is established again. A fresh database
-- has no such rows and starts on the active revision.

CREATE TABLE email_policy_activations (
    scope        TEXT PRIMARY KEY,
    revision     BIGINT NOT NULL CHECK (revision > 0),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE principals ADD COLUMN email_policy_revision BIGINT;

UPDATE principals SET email_policy_revision = 0 WHERE principal_type = 'email';

ALTER TABLE principals ADD CONSTRAINT principals_email_policy_revision
    CHECK ((principal_type = 'email') = (email_policy_revision IS NOT NULL));

-- How each key carried across a revision change was settled.
CREATE TABLE email_policy_dispositions (
    principal_id  UUID PRIMARY KEY REFERENCES principals (id) ON DELETE CASCADE,
    from_revision BIGINT NOT NULL,
    to_revision   BIGINT NOT NULL,
    disposition   TEXT NOT NULL CHECK (disposition IN ('migrated', 'quarantined')),
    reason        TEXT NOT NULL,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO email_policy_dispositions (principal_id, from_revision, to_revision, disposition, reason)
SELECT id, 0, 1, 'quarantined', 'no_source_evidence'
FROM principals WHERE principal_type = 'email';

INSERT INTO email_policy_activations (scope, revision) VALUES ('installation', 1);

-- The fence: an email key is written (inserted, or its value or revision
-- changed) only under the active revision, and no other principal carries a
-- revision.
CREATE FUNCTION principals_email_policy_fence() RETURNS trigger AS $$
BEGIN
    IF (NEW.principal_type = 'email') <> (NEW.email_policy_revision IS NOT NULL)
       OR (NEW.principal_type = 'email'
           AND (TG_OP = 'INSERT'
                OR NEW.value IS DISTINCT FROM OLD.value
                OR NEW.email_policy_revision IS DISTINCT FROM OLD.email_policy_revision)
           AND NEW.email_policy_revision IS DISTINCT FROM
               (SELECT revision FROM email_policy_activations WHERE scope = 'installation'))
    THEN
        RAISE EXCEPTION 'email key written under policy revision %, not the active one',
            NEW.email_policy_revision
            USING ERRCODE = 'SIDEP';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER principals_email_policy_fence
    BEFORE INSERT OR UPDATE OF value, email_policy_revision, principal_type ON principals
    FOR EACH ROW EXECUTE FUNCTION principals_email_policy_fence();
