// SPDX-License-Identifier: AGPL-3.0-only
//! The field-encryption key manager of this server.
//!
//! The master secret lives in a file outside the database (sealed
//! configuration); the non-secret parameters of each key version live in the
//! database, so any replica holding the same master derives the same keys.

use std::path::Path;
use std::sync::Arc;

use secrecy::SecretBox;
use sid_core::models::AuditEntry;
use sid_keys::{KeyManager, KeyVersionParams, RustCryptoPrimitives, SoftwareKeyManager};
use sid_plugin::StorageBackend;

/// Length of the master secret file, in bytes.
const MASTER_LEN: usize = 32;

/// Why the key manager could not be built.
#[derive(Debug, thiserror::Error)]
pub enum FieldKeyError {
    #[error("master key file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("master key file {0} must hold exactly 32 bytes")]
    Length(String),
    #[error("key versions: {0}")]
    Storage(#[from] sid_core::Error),
    #[error("key manager: {0}")]
    KeyManager(#[from] sid_keys::KeyManagerError),
}

/// Read the master secret from `path`, creating it with fresh random bytes
/// (owner-only permissions) when it does not exist yet.
pub fn load_or_create_master(path: &Path) -> Result<SecretBox<[u8; 32]>, FieldKeyError> {
    let io = |source| FieldKeyError::Io {
        path: path.display().to_string(),
        source,
    };
    if !path.exists() {
        use rand::RngCore;
        use std::io::Write;
        let mut bytes = zeroize::Zeroizing::new([0u8; MASTER_LEN]);
        rand::rngs::OsRng.fill_bytes(bytes.as_mut());
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(mut file) => {
                file.write_all(bytes.as_ref()).map_err(io)?;
                file.sync_all().map_err(io)?;
                tracing::warn!(
                    "Generated field-encryption master key at '{}': back it up outside the database",
                    path.display()
                );
            }
            // Another process created it first; read theirs below.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io(e)),
        }
    }
    let data = zeroize::Zeroizing::new(std::fs::read(path).map_err(io)?);
    let master: [u8; MASTER_LEN] = data
        .as_slice()
        .try_into()
        .map_err(|_| FieldKeyError::Length(path.display().to_string()))?;
    Ok(SecretBox::new(Box::new(master)))
}

/// Key versions from storage, creating version 1 on first start. Concurrent
/// starters agree: only one insert of a version succeeds and all re-read it.
pub async fn load_or_create_versions(
    storage: &dyn StorageBackend,
) -> Result<Vec<KeyVersionParams>, FieldKeyError> {
    let versions = storage.list_key_versions().await?;
    if !versions.is_empty() {
        return Ok(versions);
    }
    use rand::RngCore;
    let mut salt = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    storage
        .insert_key_version(
            &KeyVersionParams::new(1, salt, "key-v1"),
            AuditEntry::system("crypto.key_version_created", "key_version:1").into(),
        )
        .await?;
    Ok(storage.list_key_versions().await?)
}

/// Build the key manager from the master file and the stored versions.
pub async fn field_key_manager(
    storage: &dyn StorageBackend,
    master_path: &Path,
) -> Result<Arc<dyn KeyManager>, FieldKeyError> {
    let master = load_or_create_master(master_path)?;
    let versions = load_or_create_versions(storage).await?;
    let manager = SoftwareKeyManager::new(master, versions, Arc::new(RustCryptoPrimitives::new()))?;
    Ok(Arc::new(manager))
}

#[cfg(test)]
mod tests;
