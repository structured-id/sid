-- Invite listing pages in one total order (newest first, then id); the
-- index serves that order.
CREATE INDEX IF NOT EXISTS idx_invites_created_id ON invites (created_at DESC, id DESC);
