-- Applications: the managed container of an OAuth client role, a protected
-- resource role, or both. A project holding applications is not deleted.
CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id),
    name TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    -- Target of the composite key below: a role's project is its application's.
    UNIQUE (id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_applications_project ON applications (project_id);

-- Every existing client becomes the client role of an application of its own,
-- named after it. The id is a UUIDv7 carrying the client's creation time:
-- random bits with the 48-bit millisecond timestamp in front and the version
-- nibble set to 7 (RFC 9562 §5.7); PostgreSQL 16 has no uuidv7().
ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS application_id UUID;

WITH generated AS MATERIALIZED (
    SELECT client_id, project_id, client_name, created_at,
           encode(
               set_bit(set_bit(
                   overlay(uuid_send(gen_random_uuid())
                           PLACING substring(int8send(
                               (extract(epoch FROM created_at) * 1000)::bigint) FROM 3)
                           FROM 1 FOR 6),
                   52, 1), 53, 1),
               'hex')::uuid AS id
    FROM oauth2_clients
    WHERE application_id IS NULL
), inserted AS (
    INSERT INTO applications (id, project_id, name, revision, created_at, updated_at)
    SELECT id, project_id, client_name, 0, created_at, created_at FROM generated
)
UPDATE oauth2_clients c SET application_id = g.id
FROM generated g WHERE c.client_id = g.client_id;

ALTER TABLE oauth2_clients ALTER COLUMN application_id SET NOT NULL;
-- One client role per application, in the application's project.
ALTER TABLE oauth2_clients
    ADD CONSTRAINT oauth2_clients_application_unique UNIQUE (application_id);
ALTER TABLE oauth2_clients
    ADD CONSTRAINT oauth2_clients_application_fk
    FOREIGN KEY (application_id, project_id) REFERENCES applications (id, project_id);

-- Protected-resource roles. A row is never deleted: removing its application
-- retires it (application_id NULL), so its indicator is never given to
-- another resource of the issuer.
CREATE TABLE IF NOT EXISTS protected_resources (
    id UUID PRIMARY KEY,
    application_id UUID UNIQUE REFERENCES applications(id),
    issuer_id UUID NOT NULL REFERENCES oidc_issuers(id),
    indicator TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('active', 'inactive', 'retired')),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (issuer_id, indicator),
    CHECK ((state = 'retired') = (application_id IS NULL))
);

-- Explicit permission of one client to obtain tokens for one resource. The
-- client is an OAuth client or a machine user; `client_id` is its identifier
-- either way.
CREATE TABLE IF NOT EXISTS resource_access (
    oauth_client_id TEXT REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    machine_client_id VARCHAR(255) REFERENCES machine_users(client_id) ON DELETE CASCADE,
    client_id TEXT GENERATED ALWAYS AS (COALESCE(oauth_client_id, machine_client_id)) STORED,
    resource_id UUID NOT NULL REFERENCES protected_resources(id),
    scopes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (num_nonnulls(oauth_client_id, machine_client_id) = 1),
    PRIMARY KEY (client_id, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_resource_access_resource ON resource_access (resource_id);

-- The resource a client's token is for when a request names none.
ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS default_resource UUID REFERENCES protected_resources(id);
