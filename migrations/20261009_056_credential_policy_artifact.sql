-- A password's policy verdict names the verifying artifact (the identity of
-- the verifying key) that accepted its proof, so the verdicts of an artifact
-- later retired as unsound can be found and stop counting as verified.
ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS zkpp_artifact BYTEA
        CHECK (octet_length(zkpp_artifact) = 32);

-- Verdicts recorded before artifacts were named cannot be attributed to an
-- accepted artifact: proofs from the earlier relation (its binding was
-- unsound) are indistinguishable from later ones. Their provenance is kept
-- here and the password reads as policy-unverified until its next proved
-- registration. Old copies of the database keep their original rows.
CREATE TABLE IF NOT EXISTS credential_policy_evidence_legacy (
    credential_id   UUID PRIMARY KEY,
    profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    zkpp_verified   BOOLEAN NOT NULL,
    policy_version  INTEGER,
    reason          TEXT NOT NULL CHECK (reason IN ('artifact_not_recorded')),
    demoted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO credential_policy_evidence_legacy (credential_id, profile_id, zkpp_verified, policy_version, reason)
SELECT id, profile_id, zkpp_verified, policy_version, 'artifact_not_recorded'
FROM credentials
WHERE zkpp_artifact IS NULL AND (zkpp_verified OR policy_version IS NOT NULL)
ON CONFLICT (credential_id) DO NOTHING;

UPDATE credentials SET zkpp_verified = FALSE, policy_version = NULL
WHERE zkpp_artifact IS NULL AND (zkpp_verified OR policy_version IS NOT NULL);

-- A verdict always has its policy and artifact; an unverified row has neither.
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_policy_evidence;
ALTER TABLE credentials ADD CONSTRAINT credentials_policy_evidence
    CHECK ((zkpp_verified AND policy_version IS NOT NULL AND zkpp_artifact IS NOT NULL)
        OR (NOT zkpp_verified AND policy_version IS NULL AND zkpp_artifact IS NULL));
