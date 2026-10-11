-- A login looked up regardless of case, as a SCIM directory matches a user by
-- `userName eq` (RFC 7643 §4.1.1: userName is not case-exact), uses this
-- index instead of scanning every login of its type. The value is folded
-- under the built-in `pg_c_utf8` collation, as the lookup folds it: Unicode
-- lower case whatever locale the database was created with.
CREATE INDEX IF NOT EXISTS idx_principals_type_folded_value
    ON principals (principal_type, lower(value COLLATE pg_c_utf8));
