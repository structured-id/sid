-- Public keys a `private_key_jwt` client signs its assertions with
-- (RFC 7591 §2 `jwks`), as the JSON text of a JWK Set. A client registered for
-- that method before had none and could not authenticate by it.
ALTER TABLE oauth2_clients ADD COLUMN jwks TEXT;
