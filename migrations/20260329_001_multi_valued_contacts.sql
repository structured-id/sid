-- Multi-valued contact tables: profile_phones + profile_emails
-- Replaces scalar Profile.email/phone/email_verified/phone_verified

-- ── Profile Phones ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS profile_phones (
    id                  UUID PRIMARY KEY,
    profile_id          UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    e164                BIGINT NOT NULL,
    extension           INTEGER,
    label               VARCHAR(50) NOT NULL DEFAULT 'mobile',
    custom_label        VARCHAR(100),
    is_primary          BOOLEAN NOT NULL DEFAULT false,
    can_receive_sms     BOOLEAN NOT NULL DEFAULT true,
    can_receive_fax     BOOLEAN NOT NULL DEFAULT false,
    can_receive_voice   BOOLEAN NOT NULL DEFAULT true,
    verified            BOOLEAN NOT NULL DEFAULT false,
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_phones_profile_e164
    ON profile_phones (profile_id, e164);

-- At most one primary phone per profile
CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_phones_primary
    ON profile_phones (profile_id) WHERE is_primary = true;

CREATE INDEX IF NOT EXISTS idx_profile_phones_profile_id
    ON profile_phones (profile_id);

DROP TRIGGER IF EXISTS update_profile_phones_updated_at ON profile_phones;
CREATE TRIGGER update_profile_phones_updated_at
    BEFORE UPDATE ON profile_phones
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ── Profile Emails ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS profile_emails (
    id              UUID PRIMARY KEY,
    profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    label           VARCHAR(50) NOT NULL DEFAULT 'personal',
    custom_label    VARCHAR(100),
    is_primary      BOOLEAN NOT NULL DEFAULT false,
    verified        BOOLEAN NOT NULL DEFAULT false,
    verified_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_emails_profile_email
    ON profile_emails (profile_id, email);

-- At most one primary email per profile
CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_emails_primary
    ON profile_emails (profile_id) WHERE is_primary = true;

CREATE INDEX IF NOT EXISTS idx_profile_emails_profile_id
    ON profile_emails (profile_id);

-- Global email lookup (for login resolution fallback)
CREATE INDEX IF NOT EXISTS idx_profile_emails_email
    ON profile_emails (email);

DROP TRIGGER IF EXISTS update_profile_emails_updated_at ON profile_emails;
CREATE TRIGGER update_profile_emails_updated_at
    BEFORE UPDATE ON profile_emails
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ── Migrate existing data ───────────────────────────────────────────

-- Move existing Profile.email → profile_emails (as primary)
INSERT INTO profile_emails (id, profile_id, email, label, is_primary, verified, created_at, updated_at)
SELECT
    gen_random_uuid(),
    id,
    email,
    'personal',
    true,
    email_verified,
    created_at,
    updated_at
FROM profiles
WHERE email IS NOT NULL AND email != ''
ON CONFLICT DO NOTHING;

-- Move existing Profile.phone → profile_phones (as primary)
-- Parse phone string to BIGINT: strip '+' prefix and non-digit chars
INSERT INTO profile_phones (id, profile_id, e164, label, is_primary, verified, created_at, updated_at)
SELECT
    gen_random_uuid(),
    id,
    CAST(regexp_replace(phone, '[^0-9]', '', 'g') AS BIGINT),
    'mobile',
    true,
    phone_verified,
    created_at,
    updated_at
FROM profiles
WHERE phone IS NOT NULL AND phone != '' AND regexp_replace(phone, '[^0-9]', '', 'g') != ''
ON CONFLICT DO NOTHING;

-- ── Drop old scalar columns ─────────────────────────────────────────

-- Drop the email index before dropping the column
DROP INDEX IF EXISTS idx_profiles_email;

ALTER TABLE profiles DROP COLUMN IF EXISTS email CASCADE;
ALTER TABLE profiles DROP COLUMN IF EXISTS email_verified CASCADE;
ALTER TABLE profiles DROP COLUMN IF EXISTS phone CASCADE;
ALTER TABLE profiles DROP COLUMN IF EXISTS phone_verified CASCADE;

-- ── Update Principal source_field → typed FKs ───────────────────────

ALTER TABLE principals ADD COLUMN IF NOT EXISTS source_email_id UUID REFERENCES profile_emails(id) ON DELETE SET NULL;
ALTER TABLE principals ADD COLUMN IF NOT EXISTS source_phone_id UUID REFERENCES profile_phones(id) ON DELETE SET NULL;

-- Migrate existing source_field references
UPDATE principals p
SET source_email_id = pe.id
FROM profile_emails pe
WHERE p.source_field = 'email'
  AND p.principal_type = 'Email'
  AND pe.profile_id = p.profile_id
  AND pe.is_primary = true;

UPDATE principals p
SET source_phone_id = pp.id
FROM profile_phones pp
WHERE p.source_field = 'phone'
  AND p.principal_type = 'Phone'
  AND pp.profile_id = p.profile_id
  AND pp.is_primary = true;

-- source_field column kept for now (removed in 702d when code migrates to source_email_id/source_phone_id)
-- ALTER TABLE principals DROP COLUMN IF EXISTS source_field;
