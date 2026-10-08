-- Anomaly event log: persistent storage for security rule matches.
-- Append-only. Queried by SecurityService.GetAnomalyEventLog RPC.

CREATE TABLE IF NOT EXISTS anomaly_events (
    id          UUID PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    profile_id  TEXT NOT NULL DEFAULT '',
    ip_address  TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    risk_score  INTEGER NOT NULL DEFAULT 0,
    reaction    TEXT NOT NULL DEFAULT '',
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_anomaly_events_timestamp ON anomaly_events (timestamp DESC);
CREATE INDEX idx_anomaly_events_rule_id ON anomaly_events (rule_id);
CREATE INDEX idx_anomaly_events_profile_id ON anomaly_events (profile_id) WHERE profile_id != '';
