-- The password-history evaluator keeps its keys and lifecycle in its own store
-- (migrations/history_keys), keyed by the owner's history input domain. The
-- credential service's tables keep only each epoch's public descriptor and the
-- retained entries.
--
-- The layout this converts was never part of a release: it existed only in
-- development builds. Only an empty history layout is converted: keys sealed
-- for the former owner binding cannot be moved without the evaluator's key
-- manager, and no conversion is provided for an unreleased format. When any
-- history data exists this migration refuses before changing anything, so the
-- data is kept and the migration is not recorded as applied; it never deletes
-- history to proceed. The tables are locked first, so no concurrent write can
-- land between the check and the change.

LOCK TABLE password_histories, password_history_epochs, password_history_entries,
    password_history_lifecycle, password_history_replaced, password_history_uses
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM password_histories)
        OR EXISTS (SELECT 1 FROM password_history_epochs)
        OR EXISTS (SELECT 1 FROM password_history_entries)
        OR EXISTS (SELECT 1 FROM password_history_lifecycle)
        OR EXISTS (SELECT 1 FROM password_history_replaced)
        OR EXISTS (SELECT 1 FROM password_history_uses)
    THEN
        RAISE EXCEPTION 'password history data exists in the pre-release history layout; this release converts only an empty history and changed nothing (the data is kept)';
    END IF;
END
$$;

DROP TABLE password_history_uses;
DROP TABLE password_history_replaced;
DROP TABLE password_history_lifecycle;

ALTER TABLE password_history_epochs DROP COLUMN wrapped_key;

-- The history write cutoff: no entry is written under an epoch whose key was
-- created before `not_before`. One row, present from here on, so a commit
-- always has a row to lock against a raise; NULL means no cutoff was set.
-- The epochs' `created_at` is the evaluator's key creation instant.
CREATE TABLE password_history_write_cutoff (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    not_before TIMESTAMPTZ
);
INSERT INTO password_history_write_cutoff (singleton) VALUES (TRUE);
