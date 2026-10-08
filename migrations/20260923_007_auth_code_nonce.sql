-- The OIDC nonce of the authorization request travels with the code to the
-- token endpoint, which returns it in the ID Token (OIDC Core §3.1.3.6).
ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS nonce TEXT;
