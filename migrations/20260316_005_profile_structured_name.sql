-- Profile structured name: replace display_name with OIDC/SCIM name components.
-- OIDC Core 1.0 §5.1 + SCIM RFC 7643 §4.1.1
--
-- display_name → given_name (rename, preserves existing data)
-- New: family_name, middle_name, honorific_prefix, honorific_suffix

-- Step 1: Rename display_name → given_name (preserves existing values as unstructured name).
ALTER TABLE profiles RENAME COLUMN display_name TO given_name;

-- Step 2: Add structured name columns.
ALTER TABLE profiles ADD COLUMN family_name VARCHAR(255);
ALTER TABLE profiles ADD COLUMN middle_name VARCHAR(255);
ALTER TABLE profiles ADD COLUMN honorific_prefix VARCHAR(100);
ALTER TABLE profiles ADD COLUMN honorific_suffix VARCHAR(100);
