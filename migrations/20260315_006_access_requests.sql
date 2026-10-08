-- Access requests for CE governance (1-step approval)
CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY,
    requester_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role_key TEXT NOT NULL,
    justification TEXT,
    requested_duration_hours INT,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewed_by UUID REFERENCES profiles(id),
    review_comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_id);
