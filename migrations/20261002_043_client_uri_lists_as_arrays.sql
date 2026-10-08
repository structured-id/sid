-- Redirect URIs and contacts become arrays. A comma is valid inside a URI
-- (RFC 3986 §2.2) and a quoted e-mail local part (RFC 5322 §3.4.1), so the
-- comma-joined text turned one validated value into several unvalidated
-- ones on read. Stored rows keep the items they were read as.
ALTER TABLE oauth2_clients
    ALTER COLUMN redirect_uris DROP DEFAULT,
    ALTER COLUMN redirect_uris TYPE TEXT[]
        USING COALESCE(string_to_array(NULLIF(redirect_uris, ''), ','), '{}'),
    ALTER COLUMN redirect_uris SET DEFAULT '{}',
    ALTER COLUMN contacts DROP DEFAULT,
    ALTER COLUMN contacts TYPE TEXT[]
        USING COALESCE(string_to_array(NULLIF(contacts, ''), ','), '{}'),
    ALTER COLUMN contacts SET DEFAULT '{}';
