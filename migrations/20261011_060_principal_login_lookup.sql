-- A login looked up regardless of case, as a SCIM directory matches a user by
-- `userName eq` (RFC 7643 §4.1.1: userName is not case-exact), uses this
-- index instead of scanning every login of its type.
CREATE INDEX IF NOT EXISTS idx_principals_type_lower_value
    ON principals (principal_type, lower(value));
