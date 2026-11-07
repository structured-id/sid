// SPDX-License-Identifier: AGPL-3.0-only
//! The encrypted snapshot archive. A snapshot is never written unencrypted:
//! it carries credential records, sealed server secrets and user data.
//!
//! Layout: the magic `SIDSNAP\x01`, the header length as a big-endian u32,
//! the JSON header (the manifest: format, snapshot id, creation time, source
//! backend, installation organization, SHA-256 of the snapshot and the
//! nonce), then the snapshot encrypted with AES-256-GCM under the archive
//! key, everything before it authenticated as associated data. The archive
//! key protects this archive only: it is not a key-encryption key, opens no
//! sealed field and does not replace independent recovery of server keys.

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use sid_crypto::CryptoPrimitives;

use super::{FORMAT_VERSION, Result, Snapshot, SnapshotError};

/// The first bytes of every archive of this layout.
const MAGIC: &[u8; 8] = b"SIDSNAP\x01";

/// The largest header an archive may declare; a real one is a few hundred
/// bytes.
const MAX_HEADER: usize = 64 * 1024;

fn archive(what: impl Into<String>) -> SnapshotError {
    SnapshotError::Archive(what.into())
}

/// The 256-bit key an archive is encrypted under, held by the operator.
pub struct ArchiveKey(SecretBox<[u8; 32]>);

impl ArchiveKey {
    /// The key whose 32 raw bytes are `bytes`, as an archive key file holds
    /// them.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| archive("an archive key is exactly 32 bytes"))?;
        Ok(Self(SecretBox::new(Box::new(key))))
    }
}

impl std::fmt::Debug for ArchiveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchiveKey([REDACTED])")
    }
}

/// What an archive declares about its snapshot, readable without its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The snapshot format inside.
    pub format: u32,
    pub snapshot_id: uuid::Uuid,
    pub created_at: DateTime<Utc>,
    pub source_backend: String,
    pub installation_org: Option<sid_core::models::OrgId>,
    /// SHA-256 of the snapshot JSON, checked after decryption.
    pub snapshot_sha256: [u8; 32],
    nonce: [u8; 12],
}

/// `snapshot` sealed under `key`.
pub fn seal(
    snapshot: &Snapshot,
    key: &ArchiveKey,
    crypto: &dyn CryptoPrimitives,
) -> Result<Vec<u8>> {
    let payload = snapshot.to_json()?;
    let manifest = Manifest {
        format: FORMAT_VERSION,
        snapshot_id: snapshot.metadata.snapshot_id,
        created_at: snapshot.metadata.created_at,
        source_backend: snapshot.metadata.source_backend.clone(),
        installation_org: snapshot.metadata.installation_org,
        snapshot_sha256: crypto.sha256(&payload),
        nonce: crypto
            .random_nonce()
            .map_err(|e| archive(format!("nonce: {e}")))?,
    };
    let header = serde_json::to_vec(&manifest).map_err(|e| archive(format!("manifest: {e}")))?;
    let length = u32::try_from(header.len()).map_err(|_| archive("manifest too large"))?;
    let mut sealed = Vec::with_capacity(MAGIC.len() + 4 + header.len() + payload.len() + 16);
    sealed.extend_from_slice(MAGIC);
    sealed.extend_from_slice(&length.to_be_bytes());
    sealed.extend_from_slice(&header);
    let ciphertext = crypto
        .aes_256_gcm_encrypt(key.0.expose_secret(), &manifest.nonce, &payload, &sealed)
        .map_err(|e| archive(format!("encrypt: {e}")))?;
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// The manifest of `sealed` and where its ciphertext starts, read without
/// its key.
fn header(sealed: &[u8]) -> Result<(Manifest, usize)> {
    let rest = sealed
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| archive("not a SID snapshot archive"))?;
    let (length, rest) = rest
        .split_first_chunk::<4>()
        .ok_or_else(|| archive("truncated archive"))?;
    let length = u32::from_be_bytes(*length) as usize;
    if length > MAX_HEADER || length > rest.len() {
        return Err(archive("archive manifest length out of range"));
    }
    let manifest: Manifest =
        serde_json::from_slice(&rest[..length]).map_err(|e| archive(format!("manifest: {e}")))?;
    Ok((manifest, MAGIC.len() + 4 + length))
}

/// What `sealed` declares about its snapshot, without opening it.
pub fn manifest(sealed: &[u8]) -> Result<Manifest> {
    Ok(header(sealed)?.0)
}

/// The snapshot `sealed` holds, opened under `key`: its manifest and contents
/// authenticated, its digest and identity matching what the manifest
/// declares, its format this build's.
pub fn open(sealed: &[u8], key: &ArchiveKey, crypto: &dyn CryptoPrimitives) -> Result<Snapshot> {
    let (manifest, start) = header(sealed)?;
    if manifest.format != FORMAT_VERSION {
        return Err(SnapshotError::Format(manifest.format));
    }
    let (aad, ciphertext) = sealed.split_at(start);
    let payload = crypto
        .aes_256_gcm_decrypt(key.0.expose_secret(), &manifest.nonce, ciphertext, aad)
        .map_err(|_| archive("the archive does not open under this key, or was changed"))?;
    if crypto.sha256(&payload) != manifest.snapshot_sha256 {
        return Err(archive("the snapshot does not match its manifest digest"));
    }
    let snapshot = Snapshot::parse(&payload)?;
    if snapshot.metadata.snapshot_id != manifest.snapshot_id
        || snapshot.metadata.installation_org != manifest.installation_org
    {
        return Err(archive("the snapshot does not match its manifest"));
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests;
