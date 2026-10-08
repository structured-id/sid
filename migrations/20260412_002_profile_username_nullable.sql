-- Make profiles.username nullable — user may register with email/phone only.
-- Username is a valuable identity claimed explicitly, never auto-generated.
ALTER TABLE profiles ALTER COLUMN username DROP NOT NULL;
