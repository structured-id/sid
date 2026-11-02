// SPDX-License-Identifier: AGPL-3.0-only
//! Stored form of field-encryption key version parameters, shared by backends.

use sid_core::{Error as SidError, Result as SidResult};

/// Stored name of a key derivation algorithm.
pub(crate) fn key_derivation_name(algorithm: sid_keys::KeyDerivation) -> &'static str {
    match algorithm {
        sid_keys::KeyDerivation::HkdfSha256 => "hkdf_sha256",
    }
}

/// Rebuild key version parameters from their stored columns. An unknown
/// algorithm is an error, never a guess: a wrong derivation yields a wrong key.
pub(crate) fn key_version_params(
    version: u32,
    salt: Vec<u8>,
    algorithm: &str,
    context: String,
) -> SidResult<sid_keys::KeyVersionParams> {
    match algorithm {
        "hkdf_sha256" => Ok(sid_keys::KeyVersionParams::new(version, salt, context)),
        other => Err(SidError::Storage(format!(
            "key version {version}: unknown derivation {other}"
        ))),
    }
}
