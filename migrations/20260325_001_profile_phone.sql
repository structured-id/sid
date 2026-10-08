-- Add phone and phone_verified to profiles table (denormalized from Principal for OIDC phone_number claim).
-- Follows same pattern as email/email_verified.
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT false;
