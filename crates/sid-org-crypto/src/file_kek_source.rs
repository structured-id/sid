// SPDX-License-Identifier: AGPL-3.0-only
//! KEK from a directory the deployment mounts (a Kubernetes Secret volume
//! mounted as a directory, a tmpfs on a host). The service reads the files
//! and never the orchestrator's API:
//! - `kek_version`: the current version, decimal; required;
//! - `kek.<n>`: version `n`'s KEK (32 raw bytes or 64 hex characters), one
//!   file per retained version, never changed once written, so ciphertext
//!   and restored backups under an older version stay readable.
//!
//! A version's bytes come only from its own file: nothing else is read as
//! version `n`, so a wrap is never recorded under a version its bytes do not
//! belong to. Rotation delivers `kek.<n+1>` to every replica before
//! `kek_version` names it.
//!
//! Every fetch reads the mount again, so a rotated KEK is seen without a
//! restart. Pair with [`KekCache`](crate::kek_cache::KekCache) to hold it
//! only within the cache's TTL; the mounted copy is outside that TTL.

use std::path::PathBuf;

use async_trait::async_trait;
use secrecy::SecretBox;
use zeroize::Zeroizing;

use crate::error::OrgCryptoError;
use crate::kek_source::KekSource;

/// The file naming the current version in the mounted directory.
pub const VERSION_FILE: &str = "kek_version";

/// KEK from a mounted directory.
pub struct FileKekSource {
    dir: PathBuf,
}

impl FileKekSource {
    /// The KEK versions mounted in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The bytes of file `name`; a missing or unreadable file is refused.
    async fn read(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, OrgCryptoError> {
        let path = self.dir.join(name);
        tokio::fs::read(&path)
            .await
            .map(Zeroizing::new)
            .map_err(|e| OrgCryptoError::KekUnavailable(format!("{}: {e}", path.display())))
    }
}

/// The KEK in `value`: 32 raw bytes, optionally followed by one newline the
/// file was written with (33 bytes are never a raw key, so the newline is
/// unambiguous, while a raw key's own trailing whitespace stays), or 64 hex
/// characters followed by any trailing ASCII whitespace.
fn decode_kek(value: &[u8]) -> Result<[u8; 32], OrgCryptoError> {
    let raw = match value {
        [key @ .., b'\n'] if key.len() == 32 => key,
        key => key,
    };
    if let Ok(raw) = <[u8; 32]>::try_from(raw) {
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
        let bytes = self.read(&format!("kek.{version}")).await?;
        Ok(SecretBox::new(Box::new(decode_kek(&bytes)?)))
    }

    async fn current_version(&self) -> Result<u32, OrgCryptoError> {
        let text = self.read(VERSION_FILE).await?;
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

    fn kind(&self) -> &'static str {
        "file"
    }
}

#[cfg(test)]
mod tests;
