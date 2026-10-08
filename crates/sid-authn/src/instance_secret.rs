// SPDX-License-Identifier: AGPL-3.0-only
//! Secrets every replica of an instance shares.
//!
//! The first replica to start creates the secret, seals it under the key
//! manager and stores it once; every replica and every restart opens that
//! same value. Nothing comes from a per-process random value or an
//! environment variable, so replicas never disagree on it.

use sid_core::models::{AuditEntry, InstanceSecret};
use sid_keys::KeyManager;
use sid_plugin::StorageBackend;
use zeroize::Zeroizing;

use crate::sealed_secret::{self, SealedSecretError};

/// Why an instance secret could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum InstanceSecretError<E: std::error::Error + 'static> {
    #[error("creating the instance secret: {0}")]
    Create(#[source] E),
    #[error("stored instance secret: {0}")]
    Sealed(#[from] SealedSecretError),
    #[error("instance secret storage: {0}")]
    Storage(#[from] sid_core::Error),
    #[error("instance secret missing right after it was stored")]
    Missing,
    #[error("stored instance secret has the wrong form")]
    Malformed,
}

/// The sealing context of `secret`: a value sealed for one record is never
/// accepted as another.
pub fn context(secret: InstanceSecret) -> String {
    format!("instance:{}", secret.as_str())
}

/// The stored value of `secret`, created with `create` and stored first when
/// this is the instance's first start.
pub async fn load_or_create<E, F>(
    storage: &dyn StorageBackend,
    keys: &dyn KeyManager,
    secret: InstanceSecret,
    create: F,
) -> Result<Zeroizing<Vec<u8>>, InstanceSecretError<E>>
where
    E: std::error::Error + 'static,
    F: FnOnce() -> Result<Zeroizing<Vec<u8>>, E>,
{
    let context = context(secret);
    if storage.get_instance_secret(secret).await?.is_none() {
        let fresh = create().map_err(InstanceSecretError::Create)?;
        let sealed = sealed_secret::seal(keys, &context, &fresh).await?;
        // Replicas starting together race here: the first insert is kept and
        // every one of them reads that one back below.
        storage
            .insert_instance_secret(
                secret,
                &sealed,
                AuditEntry::system("crypto.instance_secret_created", secret.as_str()).into(),
            )
            .await?;
    }
    let stored = storage
        .get_instance_secret(secret)
        .await?
        .ok_or(InstanceSecretError::Missing)?;
    Ok(sealed_secret::open(keys, &context, &stored).await?.secret)
}

#[cfg(test)]
mod tests;
