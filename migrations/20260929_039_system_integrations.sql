-- The installation's own integrations (its account UI's client, the account
-- API and the access between them) are applications SID provisions itself.
-- Each exists at most once, so replicas provisioning together keep one.
ALTER TABLE applications ADD COLUMN system_integration TEXT;
CREATE UNIQUE INDEX applications_system_integration
    ON applications (system_integration) WHERE system_integration IS NOT NULL;
