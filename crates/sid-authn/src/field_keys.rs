// SPDX-License-Identifier: AGPL-3.0-only
//! The field-encryption key manager of an authority.
//!
//! The master secret lives in a file outside the database (sealed
//! configuration); the non-secret parameters of each key version live in the
//! authority's store, so any replica holding the same master derives the same
//! keys.

use std::path::Path;
use std::sync::Arc;

use secrecy::SecretBox;
use sid_core::models::AuditEntry;
use sid_crypto::CryptoPrimitives;
use sid_keys::{KeyManager, KeyVersionParams, SoftwareKeyManager};
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
    /// The store holds key versions made under a master that is no longer at
    /// `path`. A new master would open none of the existing data, so none is
    /// made: the original is restored from its backup.
    #[error(
        "master key file {path} is missing, but the store holds key versions made under it: \
         restore that master from its backup to this path; a new master cannot open the existing data"
    )]
    MasterMissing { path: String },
    #[error("key versions: {0}")]
    Storage(#[from] sid_core::Error),
    #[error("key manager: {0}")]
    KeyManager(#[from] sid_keys::KeyManagerError),
    #[error("key entropy: {0}")]
    Crypto(#[from] sid_crypto::CryptoError),
}

fn io_error(path: &Path) -> impl FnOnce(std::io::Error) -> FieldKeyError + '_ {
    move |source| FieldKeyError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// The master at `path`, `None` when no file is there.
fn read_master(path: &Path) -> Result<Option<SecretBox<[u8; 32]>>, FieldKeyError> {
    let data = match std::fs::read(path) {
        Ok(data) => zeroize::Zeroizing::new(data),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error(path)(e)),
    };
    let master: [u8; MASTER_LEN] = data
        .as_slice()
        .try_into()
        .map_err(|_| FieldKeyError::Length(path.display().to_string()))?;
    Ok(Some(SecretBox::new(Box::new(master))))
}

/// The directory a master at `path` is published in.
fn master_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Publish a fresh master at `path` for a custody that has no key version
/// yet, or take the one another starter published first. Every caller is a
/// starter that may record the custody's first version next, so whichever
/// master it returns, the directory holding its name is synced first: the
/// store never records a version whose master's name a power loss could
/// still take away. A custody with versions never comes here, and its opens
/// sync nothing.
fn publish_or_read_master(
    path: &Path,
    crypto: &dyn CryptoPrimitives,
) -> Result<SecretBox<[u8; 32]>, FieldKeyError> {
    let dir = master_dir(path);
    let master = match read_master(path)? {
        Some(master) => master,
        None => {
            let mut tag = [0u8; 8];
            crypto.random_bytes(&mut tag)?;
            publish_master(path, crypto, u64::from_le_bytes(tag))?;
            read_master(path)?.ok_or_else(|| {
                io_error(path)(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "the published master is gone",
                ))
            })?
        }
    };
    sync_dir(dir).map_err(io_error(path))?;
    Ok(master)
}

/// Publish a fresh master at `path` through the staging file named by `tag`.
/// The whole secret is written and synced to the staging file and then
/// linked into place: the link fails when `path` exists, so a published
/// master is never replaced and no reader sees a partial one. Losing the link
/// to another starter is not an error: theirs is the master. A staging name
/// already taken is an error, and that file is left alone: only the file
/// this call created is removed.
fn publish_master(
    path: &Path,
    crypto: &dyn CryptoPrimitives,
    tag: u64,
) -> Result<(), FieldKeyError> {
    use std::io::Write;
    let mut bytes = zeroize::Zeroizing::new([0u8; MASTER_LEN]);
    crypto.random_bytes(bytes.as_mut())?;
    let dir = master_dir(path);
    std::fs::create_dir_all(dir).map_err(io_error(path))?;
    let staging = staging_path(path, tag);
    let staging_error = |source| FieldKeyError::Io {
        path: staging.display().to_string(),
        source,
    };

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staging).map_err(staging_error)?;
    // From here the staging file is this call's own, and it goes whatever
    // the outcome.
    let written = file
        .write_all(bytes.as_ref())
        .and_then(|()| file.sync_all());
    drop(file);
    let linked =
        written
            .map_err(staging_error)
            .and_then(|()| match std::fs::hard_link(&staging, path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(io_error(path)(e)),
            });
    let removed = std::fs::remove_file(&staging);
    let won = linked?;
    removed.map_err(staging_error)?;
    if won {
        tracing::warn!(
            "Generated field-encryption master key at '{}': back it up outside the database",
            path.display()
        );
    }
    Ok(())
}

/// The staging file beside `path` a publication with `tag` writes first.
fn staging_path(path: &Path, tag: u64) -> std::path::PathBuf {
    let name = path.file_name().map_or_else(
        || std::ffi::OsString::from("master"),
        std::ffi::OsStr::to_os_string,
    );
    let mut staging = std::ffi::OsString::from(".");
    staging.push(&name);
    staging.push(format!(".{tag:016x}.staging"));
    master_dir(path).join(staging)
}

/// The directories synced, for the tests that check where the barrier
/// falls: each test counts its own directory, whatever else runs beside it.
#[cfg(test)]
static DIR_SYNCS: std::sync::Mutex<Vec<std::path::PathBuf>> = std::sync::Mutex::new(Vec::new());

/// How many times `dir` was synced.
#[cfg(test)]
fn dir_syncs_of(dir: &Path) -> usize {
    DIR_SYNCS
        .lock()
        .expect("the sync record")
        .iter()
        .filter(|synced| synced.as_path() == dir)
        .count()
}

/// Make the entries of `dir` durable, so a published master's name survives
/// a power loss. On Unix (Linux, macOS, the BSDs) this is an fsync of the
/// directory. Other platforms offer std no directory handle to flush: there
/// the file's own sync is the whole promise, and the name's durability is
/// the file system's.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    DIR_SYNCS
        .lock()
        .expect("the sync record")
        .push(dir.to_path_buf());
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// A store recording the key versions of one key custody.
#[async_trait::async_trait]
pub trait KeyVersionStore: Sync {
    async fn versions(&self) -> sid_core::Result<Vec<KeyVersionParams>>;
    async fn insert(&self, params: &KeyVersionParams, audit: AuditEntry) -> sid_core::Result<bool>;
}

/// The credential service's field keys.
#[async_trait::async_trait]
impl KeyVersionStore for dyn StorageBackend {
    async fn versions(&self) -> sid_core::Result<Vec<KeyVersionParams>> {
        self.list_key_versions().await
    }
    async fn insert(&self, params: &KeyVersionParams, audit: AuditEntry) -> sid_core::Result<bool> {
        self.insert_key_version(params, audit.into()).await
    }
}

/// The history evaluator's own key custody.
#[async_trait::async_trait]
impl KeyVersionStore for dyn sid_plugin::history_keys::HistoryKeyStore {
    async fn versions(&self) -> sid_core::Result<Vec<KeyVersionParams>> {
        self.list_key_versions().await
    }
    async fn insert(&self, params: &KeyVersionParams, audit: AuditEntry) -> sid_core::Result<bool> {
        self.insert_key_version(params, audit).await
    }
}

/// Key versions from `store`, creating version 1 on first start. Concurrent
/// starters agree: only one insert of a version succeeds and all re-read it.
pub async fn load_or_create_versions(
    store: &(impl KeyVersionStore + ?Sized),
    crypto: &dyn CryptoPrimitives,
) -> Result<Vec<KeyVersionParams>, FieldKeyError> {
    let versions = store.versions().await?;
    if !versions.is_empty() {
        return Ok(versions);
    }
    let mut salt = vec![0u8; 32];
    crypto.random_bytes(&mut salt)?;
    store
        .insert(
            &KeyVersionParams::new(1, salt, "key-v1"),
            AuditEntry::system("crypto.key_version_created", "key_version:1"),
        )
        .await?;
    Ok(store.versions().await?)
}

/// Build the key manager of the custody `store` records, from the master
/// file and the stored versions. The versions are read first and decide the
/// master's fate: none is a clean bootstrap that publishes a master and
/// version 1; any is a custody whose master must already be at
/// `master_path`, and a missing one is [`FieldKeyError::MasterMissing`],
/// never replaced. A failed read of the versions touches no file.
pub async fn field_key_manager(
    store: &(impl KeyVersionStore + ?Sized),
    master_path: &Path,
    crypto: Arc<dyn CryptoPrimitives>,
) -> Result<Arc<dyn KeyManager>, FieldKeyError> {
    let existing = store.versions().await?;
    let master = if existing.is_empty() {
        publish_or_read_master(master_path, crypto.as_ref())?
    } else {
        read_master(master_path)?.ok_or_else(|| FieldKeyError::MasterMissing {
            path: master_path.display().to_string(),
        })?
    };
    let versions = if existing.is_empty() {
        load_or_create_versions(store, crypto.as_ref()).await?
    } else {
        existing
    };
    let manager = SoftwareKeyManager::new(master, versions, crypto)?;
    Ok(Arc::new(manager))
}

#[cfg(test)]
mod tests;
