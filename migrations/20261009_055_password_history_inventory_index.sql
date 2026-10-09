-- Replacements check the owner's retained unsupported-format inventory in
-- their commit transaction. Keep that lookup independent of other owners.
CREATE INDEX IF NOT EXISTS password_history_legacy_owner
    ON password_history_legacy (owner_id);
