-- A session a browser signed in with carries the CSRF token of that browser
-- session, which the page reads through the origin-checked session context
-- and echoes on every cookie-authenticated call. A browser session stored
-- before it has none and passes no CSRF check: it signs in again.
ALTER TABLE sessions ADD COLUMN browser_csrf BYTEA;
