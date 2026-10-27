// SPDX-License-Identifier: AGPL-3.0-only
//! KEK from a directory the deployment mounts (a Kubernetes Secret volume, a
//! tmpfs on a host). The service reads the files and never the
//! orchestrator's API:
//! - `kek_version`: the current version, decimal (1 when absent);
//! - `kek.<n>`: version `n`'s KEK (32 raw bytes or 64 hex characters), one
//!   file per retained version, never changed once written, so ciphertext
//!   and restored backups under an older version stay readable;
//! - `kek`: the current version's KEK where its `kek.<n>` is absent.
//!
//! Rotation delivers `kek.<n+1>` to every replica before `kek_version`
//! names it, so no replica wraps under a version another cannot read.
//!
//! Every fetch reads the mount again, so a rotated KEK is seen without a
//! restart. Pair with [`KekCache`](crate::kek_cache::KekCache) to hold it
//! only within the cache's TTL; the mounted copy is outside that TTL.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use secrecy::SecretBox;
use zeroize::Zeroizing;

use crate::error::OrgCryptoError;
use crate::kek_source::KekSource;

/// The file holding the current version's KEK where its versioned file is
/// absent; version `n`'s own file is `kek.<n>`.
pub const KEK_FILE: &str = "kek";
/// The file holding the KEK's version in the mounted directory.
pub const VERSION_FILE: &str = "kek_version";

/// KEK from a mounted directory.
pub struct FileKekSource {
    dir: PathBuf,
}

impl FileKekSource {
    /// The KEK mounted in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    async fn read(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, OrgCryptoError> {
        let path = self.dir.join(name);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(unavailable(&path, e)),
        }
    }

    async fn version(&self) -> Result<u32, OrgCryptoError> {
        let Some(text) = self.read(VERSION_FILE).await? else {
            return Ok(1);
        };
        std::str::from_utf8(&text)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| {
                OrgCryptoError::KekUnavailable(format!(
                    "{}: not a decimal version",
                    self.dir.join(VERSION_FILE).display()
                ))
            })
    }
}

fn unavailable(path: &Path, e: std::io::Error) -> OrgCryptoError {
    OrgCryptoError::KekUnavailable(format!("{}: {e}", path.display()))
}

/// The KEK in `value`: 32 raw bytes, or 64 hex characters; trailing ASCII
/// whitespace (a newline the file was written with) is not part of it.
fn decode_kek(value: &[u8]) -> Result<[u8; 32], OrgCryptoError> {
    if let Ok(raw) = <[u8; 32]>::try_from(value) {
        return Ok(raw);
    }
    let trimmed = value.trim_ascii_end();
    if trimmed.len() == 64 && trimmed.iter().all(u8::is_ascii_hexdigit) {
        let mut kek = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut kek)?;
        return Ok(kek);
    }
    Err(OrgCryptoError::InvalidKekLength(trimmed.len()))
}

#[async_trait]
impl KekSource for FileKekSource {
    async fn fetch_kek(&self, version: u32) -> Result<SecretBox<[u8; 32]>, OrgCryptoError> {
        // A versioned file holds one version for good: no other file needs
        // to agree with it.
        if let Some(bytes) = self.read(&format!("{KEK_FILE}.{version}")).await? {
            return Ok(SecretBox::new(Box::new(decode_kek(&bytes)?)));
        }
        let current = self.version().await?;
        if current != version {
            return Err(OrgCryptoError::KekVersionMismatch {
                have: current,
                need: version,
            });
        }
        let bytes = self.read(KEK_FILE).await?.ok_or_else(|| {
            unavailable(
                &self.dir.join(KEK_FILE),
                std::io::ErrorKind::NotFound.into(),
            )
        })?;
        // `kek` follows the current version: a version changed while it was
        // read leaves the bytes of an unknown version, refused, not used.
        if self.version().await? != current {
            return Err(OrgCryptoError::KekUnavailable(format!(
                "{}: the version changed while the KEK was read; retry",
                self.dir.display()
            )));
        }
        Ok(SecretBox::new(Box::new(decode_kek(&bytes)?)))
    }

    async fn current_version(&self) -> Result<u32, OrgCryptoError> {
        self.version().await
    }

    fn kind(&self) -> &'static str {
        "file"
    }
}

#[cfg(test)]
mod tests;
