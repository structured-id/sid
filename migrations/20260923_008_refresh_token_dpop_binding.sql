-- A refresh token issued with a DPoP proof is bound to that key: using it
-- again needs a proof for the same key (RFC 9449 §5).
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS dpop_jkt TEXT;
