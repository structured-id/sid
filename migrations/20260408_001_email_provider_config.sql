-- SPDX-License-Identifier: AGPL-3.0-only
-- Email provider configuration — instance-level singleton.
--
-- Managed via AdminService.UpdateEmailSettings (gRPC).
-- sid-notify reads this table on startup; falls back to env vars if empty.
--
-- Singleton enforcement: application always reads/writes the row with
-- id = '00000000-0000-0000-0000-000000000001' via INSERT … ON CONFLICT DO UPDATE.
--
-- Encryption field values: 'none' | 'ssl_tls' | 'starttls'
-- Auth type field values:  'none' | 'username_password'
--
-- CE: password_enc stored plaintext (no data-key infrastructure).
-- EE: password_enc encrypted at rest via EncryptedField (sid-ee-infra).

CREATE TABLE IF NOT EXISTS email_provider_config (
    id                  UUID        PRIMARY KEY,
    smtp_host           TEXT        NOT NULL DEFAULT '',
    smtp_port           INTEGER     NOT NULL DEFAULT 587,
    from_address        TEXT        NOT NULL DEFAULT '',
    from_display_name   TEXT        NOT NULL DEFAULT '',
    reply_to            TEXT        NOT NULL DEFAULT '',
    encryption          TEXT        NOT NULL DEFAULT 'starttls',
    auth_type           TEXT        NOT NULL DEFAULT 'none',
    username            TEXT        NOT NULL DEFAULT '',
    password_enc        TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
