-- Where the end-session endpoint may send the browser after logout (OIDC
-- RP-Initiated Logout 1.0 §3.1), compared exactly. A client without any is
-- never redirected after logout.
ALTER TABLE oauth2_clients
    ADD COLUMN post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}';
