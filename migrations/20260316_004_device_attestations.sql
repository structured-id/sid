-- Device management tables (devices + device_attestations).
-- devices: UX metadata tracked by sid-identity.
-- device_attestations: cryptographic identity tracked by sid-attestation.
-- Attestations are stored without verification.

CREATE TABLE IF NOT EXISTS devices (
    id                  UUID PRIMARY KEY,
    profile_id          UUID NOT NULL,
    display_name        TEXT,
    device_type         TEXT NOT NULL DEFAULT 'desktop',
    os_info             TEXT,
    assurance           TEXT NOT NULL DEFAULT 'unknown',
    trusted             BOOLEAN NOT NULL DEFAULT FALSE,
    hardware_attested   BOOLEAN NOT NULL DEFAULT FALSE,
    fingerprint_hash    TEXT,
    last_ip_geo         TEXT,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_profile_id
    ON devices (profile_id);

CREATE INDEX IF NOT EXISTS idx_devices_fingerprint
    ON devices (profile_id, fingerprint_hash)
    WHERE fingerprint_hash IS NOT NULL;

-- One attestation per device (UNIQUE on device_id).
CREATE TABLE IF NOT EXISTS device_attestations (
    id                      UUID PRIMARY KEY,
    device_id               UUID NOT NULL UNIQUE,
    profile_id              UUID NOT NULL,
    format                  TEXT NOT NULL DEFAULT 'none',
    key_storage             TEXT NOT NULL DEFAULT 'software',
    status                  TEXT NOT NULL DEFAULT 'unverified',
    device_public_key       BYTEA NOT NULL,
    attestation_object      BYTEA,
    attestation_certificate BYTEA,
    aaguid                  TEXT,
    credential_id           TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at              TIMESTAMPTZ
);

-- Fast lookup by profile (list all device attestations for a user).
CREATE INDEX IF NOT EXISTS idx_device_attestations_profile_id
    ON device_attestations (profile_id);

-- Fast lookup by status (find active/revoked attestations).
CREATE INDEX IF NOT EXISTS idx_device_attestations_status
    ON device_attestations (status);
