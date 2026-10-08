-- A provisioning connector holds roles as its own principal (the SCIM
-- provisioner role on one organization's directory resource). Its
-- assignments go with the connector.
ALTER TABLE role_assignments
    ADD COLUMN IF NOT EXISTS provisioning_connector_id UUID
    REFERENCES provisioning_connectors(id) ON DELETE CASCADE;

ALTER TABLE role_assignments DROP CONSTRAINT IF EXISTS chk_principal;
ALTER TABLE role_assignments ADD CONSTRAINT chk_principal CHECK (
    num_nonnulls(profile_id, group_id, machine_user_id, oauth_client_id,
                 provisioning_connector_id) = 1
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_provisioning_connector_id
    ON role_assignments(provisioning_connector_id);
