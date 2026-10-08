-- Constrained role administration (D050 B): an administrative assignment is an
-- ordinary role assignment carrying an envelope of what its holder may
-- administer, and every assignment records who created it on what authority.

-- Provenance and revision of every assignment. Missing provenance (rows
-- written before it was recorded) confers no delegation authority.
ALTER TABLE role_assignments ADD COLUMN granted_by TEXT;
ALTER TABLE role_assignments ADD COLUMN basis_assignment_id UUID;
-- A redelegated administrative assignment ends with its source.
ALTER TABLE role_assignments ADD COLUMN depends_on_assignment_id UUID
    REFERENCES role_assignments(id) ON DELETE CASCADE;
ALTER TABLE role_assignments ADD COLUMN revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE role_assignments ADD CONSTRAINT chk_role_assignment_provenance
    CHECK (granted_by IS NOT NULL
           OR (basis_assignment_id IS NULL AND depends_on_assignment_id IS NULL));
CREATE INDEX idx_role_assignments_depends_on ON role_assignments(depends_on_assignment_id)
    WHERE depends_on_assignment_id IS NOT NULL;

-- The envelope's scalar bounds. A group recipients are restricted to cannot be
-- deleted from under it: that would silently widen the envelope.
CREATE TABLE role_assignment_admin (
    assignment_id      UUID PRIMARY KEY REFERENCES role_assignments(id) ON DELETE CASCADE,
    recipient_group_id UUID REFERENCES groups(id) ON DELETE RESTRICT,
    max_validity_secs  BIGINT NOT NULL CHECK (max_validity_secs > 0)
);

-- The envelope's set bounds: permitted operations, recipient kinds and the
-- permission ceiling, one row per value.
CREATE TABLE role_assignment_admin_entries (
    assignment_id UUID NOT NULL REFERENCES role_assignment_admin(assignment_id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('operation', 'recipient_kind', 'permission')),
    value         TEXT NOT NULL,
    PRIMARY KEY (assignment_id, kind, value),
    CHECK (kind <> 'operation' OR value IN ('assign', 'revoke', 'edit_role', 'redelegate')),
    CHECK (kind <> 'recipient_kind'
           OR value IN ('profile', 'group', 'machine_user', 'oauth_client'))
);

-- The roles the envelope administers. A deleted role leaves the envelope:
-- that only narrows it.
CREATE TABLE role_assignment_admin_roles (
    assignment_id UUID NOT NULL REFERENCES role_assignment_admin(assignment_id) ON DELETE CASCADE,
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (assignment_id, role_id)
);
CREATE INDEX idx_role_assignment_admin_roles_role ON role_assignment_admin_roles(role_id);
