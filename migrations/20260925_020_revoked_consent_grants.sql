-- A revoked consent shares nothing: its grants end with it.
UPDATE claim_grants g SET revoked_at = c.revoked_at
FROM consents c
WHERE g.consent_id = c.id AND g.revoked_at IS NULL AND c.status = 'revoked';
