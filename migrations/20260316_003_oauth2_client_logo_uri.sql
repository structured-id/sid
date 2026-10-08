-- Add logo_uri column to oauth2_clients (OIDC Dynamic Client Registration §2).
-- Used for consent screen favicon and app launcher display.
ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS logo_uri TEXT;
