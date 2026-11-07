// SPDX-License-Identifier: AGPL-3.0-only
//! The authentication core's answers to a portable snapshot: the history
//! owner domains it keys evaluator keys by and the sealing metadata of the
//! OPAQUE server setup.

use sid_core::models::{InstanceSecret, OrgId, ProfileId};
use sid_plugin::SnapshotRules;

/// The rules of this core.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuthnSnapshotRules;

impl SnapshotRules for AuthnSnapshotRules {
    fn history_owner_domain(&self, installation: OrgId, owner: ProfileId) -> [u8; 32] {
        crate::password_history::owner_domain(installation.as_bytes(), owner)
    }

    fn opaque_setup_key_version(&self, sealed: &[u8]) -> Result<u32, String> {
        let context = crate::instance_secret::context(InstanceSecret::OpaqueServerSetup);
        let field = crate::sealed_secret::inspect(&context, sealed).map_err(|e| e.to_string())?;
        if field.ciphertext.len() <= 16 {
            return Err("the sealed setup has no encrypted payload".into());
        }
        Ok(field.key_version)
    }
}

#[cfg(test)]
mod tests;
