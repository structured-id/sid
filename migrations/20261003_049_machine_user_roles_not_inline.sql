-- A machine user's roles are RoleAssignments of its principal; the inline
-- list was never read by any authorization decision.
ALTER TABLE machine_users DROP COLUMN IF EXISTS roles;
