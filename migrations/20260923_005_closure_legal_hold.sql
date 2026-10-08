-- A legal hold freezes an account closure until it is lifted; it has to
-- survive a restart, so it is stored with the closure request.
ALTER TABLE closure_requests ADD COLUMN IF NOT EXISTS legal_hold JSONB;
