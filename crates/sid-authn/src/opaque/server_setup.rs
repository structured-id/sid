// SPDX-License-Identifier: AGPL-3.0-only
//! The OPAQUE server setup every replica shares.
//!
//! The setup (OPRF seed and server keypair, RFC 9807 §6.3.2.2) is created by
//! the first replica to start, sealed under the key manager and stored once.
//! Every replica and every restart loads that same setup, so stored password
//! records keep verifying wherever a login lands.

use std::collections::HashMap;

use sid_core::models::InstanceSecret;
use sid_keys::KeyManager;
use sid_plugin::InstanceSecretStore;
use sid_plugin::crypto::{CurveId, OpaqueError, OpaqueOperations, OpaqueSetupHandle};
use zeroize::Zeroizing;

use super::{OpaqueRouter, P256Opaque, P384Opaque, P521Opaque, PallasOpaque, RistrettoOpaque};
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
    storage: &dyn InstanceSecretStore,
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

/// The router a deployment signs in with over `storage`: new passwords on
/// Pallas under the stored setup, sign-in on every curve this build
/// implements, so records registered under an earlier primary keep working.
pub async fn router(
    storage: &dyn InstanceSecretStore,
    keys: &dyn KeyManager,
) -> Result<OpaqueRouter, ServerSetupError> {
    let primary = Box::new(PallasOpaque::new());
    let setup = load_or_create(storage, keys, primary.as_ref()).await?;
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
    verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
    verifiers.insert(CurveId::P384, Box::new(P384Opaque::new()));
    verifiers.insert(CurveId::P521, Box::new(P521Opaque::new()));
    Ok(OpaqueRouter::new(primary, verifiers, setup))
}

#[cfg(test)]
mod tests;
