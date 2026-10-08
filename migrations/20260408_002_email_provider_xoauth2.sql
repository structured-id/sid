-- SPDX-License-Identifier: AGPL-3.0-only
-- Add XOAUTH2 columns to email_provider_config.
--
-- XOAUTH2 enables Microsoft 365 and Google Workspace SMTP relay
-- without Basic Auth (deprecated by Microsoft Oct 2022).
--
-- CE stores client_secret and service_account_key in plaintext.
-- EE will extend these columns with EncryptedField wrapping.
--
-- oauth2_provider values: 'm365' | 'google'

ALTER TABLE email_provider_config
    ADD COLUMN IF NOT EXISTS oauth2_provider        TEXT,
    ADD COLUMN IF NOT EXISTS oauth2_tenant_id       TEXT,
    ADD COLUMN IF NOT EXISTS oauth2_client_id       TEXT,
    ADD COLUMN IF NOT EXISTS oauth2_client_secret   TEXT,
    ADD COLUMN IF NOT EXISTS oauth2_service_account_key TEXT,
    ADD COLUMN IF NOT EXISTS oauth2_token_endpoint  TEXT;
