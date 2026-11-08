// SPDX-License-Identifier: AGPL-3.0-only
//! What a portable snapshot needs from the authentication core to check its
//! contents: values the storage layer carries but does not define. The core
//! implements it; the snapshot's export, import and verification use it.

use sid_core::models::{OrgId, ProfileId};

pub trait SnapshotRules: Send + Sync {
    /// The password-history owner domain of `owner` in `installation`, under
    /// which the history evaluator keeps that owner's keys.
    fn history_owner_domain(&self, installation: OrgId, owner: ProfileId) -> [u8; 32];

    /// The key version the sealed OPAQUE server setup `sealed` is sealed
    /// under, read from its public metadata without opening it; or why it is
    /// not a sealed setup.
    fn opaque_setup_key_version(&self, sealed: &[u8]) -> Result<u32, String>;
}
