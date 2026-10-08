-- Migration: Add verification timestamps to principals
-- verified_at: when OTP/KYC was last confirmed
-- verification_expires: when verification status decays (verified_at + policy TTL)

ALTER TABLE principals ADD COLUMN verified_at TIMESTAMPTZ;
ALTER TABLE principals ADD COLUMN verification_expires TIMESTAMPTZ;
