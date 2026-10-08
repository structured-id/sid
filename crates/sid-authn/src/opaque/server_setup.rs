// SPDX-License-Identifier: AGPL-3.0-only
//! The OPAQUE server setup every replica shares.
//!
//! The setup (OPRF seed and server keypair, RFC 9807 §6.3.2.2) is created by
//! the first replica to start, sealed under the key manager and stored once.
//! Every replica and every restart loads that same setup, so stored password
//! records keep verifying wherever a login lands.

use sid_core::models::InstanceSecret;
use sid_keys::KeyManager;
use sid_plugin::StorageBackend;
use sid_plugin::crypto::{OpaqueError, OpaqueOperations, OpaqueSetupHandle};
use zeroize::Zeroizing;

use crate::instance_secret::{self, InstanceSecretError};

/// Why the server setup could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ServerSetupError {
    #[error("OPAQUE setup: {0}")]
    Opaque(#[from] OpaqueError),
    #[error("OPAQUE setup: {0}")]
    Stored(#[from] InstanceSecretError<OpaqueError>),
}

/// The stored server setup for `primary`, created and stored first when this
/// is the instance's first start.
pub async fn load_or_create(
    storage: &dyn StorageBackend,
    keys: &dyn KeyManager,
    primary: &dyn OpaqueOperations,
) -> Result<OpaqueSetupHandle, ServerSetupError> {
    let stored =
        instance_secret::load_or_create(storage, keys, InstanceSecret::OpaqueServerSetup, || {
            primary
                .create_setup(None)
                .map(|fresh| Zeroizing::new(fresh.0))
        })
        .await?;
    Ok(primary.setup_from_bytes(&stored)?)
}

#[cfg(test)]
mod tests;
