// SPDX-License-Identifier: AGPL-3.0-only
//! The engine's portable snapshot: an encrypted archive of an installation's
//! database, exported from a drained engine and imported into an
//! uninitialized store before its installation is opened. The format, the
//! import rules and the archive are `sid_storage::snapshot`'s; this module
//! binds them to the authentication core's rules and to the engine's
//! lifecycle.
//!
//! Export needs [`Drained`]: the engine's workers ended, so nothing it runs
//! writes while the snapshot is read. The host also stops its own calls into
//! the engine for the export; a backup does not disable the source, which
//! the host may start again afterwards. Import takes only an uninitialized
//! store, or the interrupted import of the same archive, and starts nothing:
//! the host opens the restored installation ([`crate::Installation::open`])
//! and starts its engine when it activates it, after the superseded
//! installation is stopped and the master key file is restored.

use sid_authn::snapshot_rules::AuthnSnapshotRules;
use sid_crypto::CryptoPrimitives;

pub use sid_storage::snapshot::archive::{ArchiveKey, Manifest};
use sid_storage::snapshot::{self, archive};
pub use sid_storage::snapshot::{ImportResult, Snapshot, SnapshotError, Store, VerifyResult};

use crate::lifecycle::Drained;

/// The installation in `store` as an archive sealed under `key`.
pub async fn export(
    _drained: &Drained,
    store: Store<'_>,
    key: &ArchiveKey,
    crypto: &dyn CryptoPrimitives,
) -> Result<Vec<u8>, SnapshotError> {
    let snapshot = snapshot::export(store, &AuthnSnapshotRules).await?;
    archive::seal(&snapshot, key, crypto)
}

/// What `sealed` declares about its snapshot, read without its key.
pub fn manifest(sealed: &[u8]) -> Result<Manifest, SnapshotError> {
    archive::manifest(sealed)
}

/// Import the archive `sealed`, opened under `key`, into the uninitialized
/// `store`, or resume its interrupted import there.
pub async fn import(
    store: Store<'_>,
    sealed: &[u8],
    key: &ArchiveKey,
    crypto: &dyn CryptoPrimitives,
) -> Result<ImportResult, SnapshotError> {
    let snapshot = archive::open(sealed, key, crypto)?;
    snapshot::import(store, &AuthnSnapshotRules, crypto, &snapshot).await
}

/// Compare the restored `target` with its `source`.
pub async fn verify(source: Store<'_>, target: Store<'_>) -> Result<VerifyResult, SnapshotError> {
    snapshot::verify(source, target, &AuthnSnapshotRules).await
}

#[cfg(test)]
mod tests;
