// SPDX-License-Identifier: AGPL-3.0-only
//! Credential secrets stored through the key manager.
//!
//! A secret the server must read back (a TOTP seed) is kept only as an
//! AES-256-GCM field under a key held outside the database, bound to the
//! record it belongs to, so a database dump alone yields nothing usable.

use sid_core::models::{AuditEntry, Credential, CredentialId, CredentialType, ProfileId};
use sid_keys::{EncryptedField, KeyManager, KeyManagerError};
use sid_plugin::StorageBackend;
use zeroize::Zeroizing;

/// Leads every sealed value, so a stored value is recognised as sealed
/// without guessing (the legacy form was the bare secret).
const SEALED_PREFIX: &[u8; 8] = b"\0sidkm1\0";

/// Credentials rewritten per page by [`seal_plaintext_credentials`].
const SEAL_PAGE: u32 = 200;

/// Why a sealed secret could not be produced or read.
#[derive(Debug, thiserror::Error)]
pub enum SealedSecretError {
    #[error("stored secret is not sealed")]
    NotSealed,
    #[error("sealed secret is malformed: {0}")]
    Malformed(String),
    #[error("sealed secret is bound to another record")]
    ContextMismatch,
    #[error(transparent)]
    KeyManager(#[from] KeyManagerError),
    #[error(transparent)]
    Storage(#[from] sid_core::Error),
}

/// A secret read back, and its re-encryption under the current key version
/// when it was stored under an older one (to be written back by the caller).
pub struct Opened {
    pub secret: Zeroizing<Vec<u8>>,
    pub resealed: Option<Vec<u8>>,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("secret", &"[REDACTED]")
            .field("resealed", &self.resealed.is_some())
            .finish()
    }
}

/// Binding context of a profile's TOTP seed.
pub fn totp_context(profile_id: ProfileId) -> String {
    format!("totp:{profile_id}")
}

/// Binding context of a profile's OPAQUE envelope.
pub fn opaque_context(profile_id: ProfileId) -> String {
    format!("opaque:{profile_id}")
}

/// Whether a stored value is in sealed form.
pub fn is_sealed(stored: &[u8]) -> bool {
    stored.starts_with(SEALED_PREFIX)
}

/// Encrypt `secret` for storage, bound to `context`.
pub async fn seal(
    key_manager: &dyn KeyManager,
    context: &str,
    secret: &[u8],
) -> Result<Vec<u8>, SealedSecretError> {
    let field = key_manager.encrypt(secret, context).await?;
    let mut stored = SEALED_PREFIX.to_vec();
    stored.extend_from_slice(&field.to_bytes());
    Ok(stored)
}

/// Decrypt a stored secret that must belong to `context`.
///
/// The context is checked before decryption: the AAD binds a ciphertext to
/// the context stored beside it, so a whole sealed value copied from another
/// record would otherwise decrypt as that record's secret.
pub async fn open(
    key_manager: &dyn KeyManager,
    context: &str,
    stored: &[u8],
) -> Result<Opened, SealedSecretError> {
    let field = inspect(context, stored)?;
    let secret = Zeroizing::new(key_manager.decrypt(&field).await?);
    let resealed = if key_manager.needs_rotation(&field) {
        Some(seal(key_manager, context, &secret).await?)
    } else {
        None
    };
    Ok(Opened { secret, resealed })
}

/// Read only the public sealing metadata and ciphertext. This verifies the
/// storage format and record context, not the authentication tag or key custody;
/// callers must still open the value before using its secret.
pub fn inspect(context: &str, stored: &[u8]) -> Result<EncryptedField, SealedSecretError> {
    let body = stored
        .strip_prefix(SEALED_PREFIX.as_slice())
        .ok_or(SealedSecretError::NotSealed)?;
    let field = EncryptedField::from_bytes(body)
        .map_err(|e| SealedSecretError::Malformed(e.to_string()))?;
    if field.context != context {
        return Err(SealedSecretError::ContextMismatch);
    }
    Ok(field)
}

/// Seal every credential of `credential_type` still stored in plain form,
/// with the context `context_for` gives it. Returns how many were sealed.
///
/// Idempotent: sealed values are skipped, so replicas running it at the same
/// time only repeat work; every write stores a valid sealing of the same secret.
pub async fn seal_plaintext_credentials(
    storage: &dyn StorageBackend,
    key_manager: &dyn KeyManager,
    credential_type: CredentialType,
    context_for: impl Fn(&Credential) -> String,
) -> Result<u64, SealedSecretError> {
    let mut sealed = 0u64;
    let mut after: Option<CredentialId> = None;
    loop {
        let page = storage
            .list_credentials_by_type(credential_type, after, SEAL_PAGE)
            .await?;
        let Some(last) = page.last() else {
            return Ok(sealed);
        };
        after = Some(last.id);
        for credential in page {
            if is_sealed(credential.data.expose()) {
                continue;
            }
            let stored = seal(
                key_manager,
                &context_for(&credential),
                credential.data.expose(),
            )
            .await?;
            // Another replica sealing the same value first is not an error.
            if storage
                .reseal_credential_data(
                    credential.id,
                    credential.data.expose(),
                    &stored,
                    AuditEntry::system("credential.secret_sealed", credential.id.0.to_string())
                        .into(),
                )
                .await?
            {
                sealed += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests;
