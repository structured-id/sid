-- The permission ceiling an envelope approved a working assignment under (D050 B),
-- one row per permission. Its role is never edited past it while the
-- assignment exists, whatever becomes of the envelope. No rows: the root
-- granted it, or it predates provenance.
CREATE TABLE role_assignment_ceilings (
    assignment_id UUID NOT NULL REFERENCES role_assignments(id) ON DELETE CASCADE,
    permission    TEXT NOT NULL,
    PRIMARY KEY (assignment_id, permission)
);
