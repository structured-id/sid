// SPDX-License-Identifier: AGPL-3.0-only
//! The process's JWT signature provider. JWT processing stays in
//! jsonwebtoken; its provider is process-wide and installed at most once, so
//! the binary or embedding host installs it before any token is signed or
//! verified, and a library never does.

use jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER;

/// The process's JWT signature provider was chosen before the host installed
/// one: by another installation, or by a JWT operation that ran first.
#[derive(Debug, thiserror::Error)]
#[error("the JWT signature provider of this process was already chosen")]
pub struct ProviderConflict;

/// Install aws-lc as this process's JWT signature provider. Call once, before
/// any token is signed or verified.
///
/// jsonwebtoken does not say which provider holds the slot, so any earlier
/// choice is refused rather than assumed to be aws-lc.
pub fn install_jwt_provider() -> Result<(), ProviderConflict> {
    DEFAULT_PROVIDER
        .install_default()
        .map_err(|_| ProviderConflict)
}
