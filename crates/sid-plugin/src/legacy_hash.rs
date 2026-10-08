// SPDX-License-Identifier: AGPL-3.0-only
//! Legacy hash verification plugin trait.
//!
//! Temporary capability for verifying password hashes imported from
//! competitor IdPs (Keycloak, Auth0, Okta, Zitadel, Authentik).
//! Active only during migration period; disabled after deadline.

use std::fmt;

/// Error during legacy hash verification.
#[derive(Debug)]
pub enum HashError {
    /// Hash format is invalid or corrupted.
    InvalidFormat(String),
    /// Underlying crypto library error.
    CryptoError(String),
    /// Hash algorithm not supported by this verifier.
    UnsupportedAlgorithm(String),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid hash format: {}", msg),
            Self::CryptoError(msg) => write!(f, "crypto error: {}", msg),
            Self::UnsupportedAlgorithm(msg) => write!(f, "unsupported algorithm: {}", msg),
        }
    }
}

impl std::error::Error for HashError {}

/// Temporary plugin for verifying legacy password hashes during migration.
///
/// Implementations are provider-specific (bcrypt, pbkdf2, argon2, scrypt).
/// After migration deadline, the plugin is disabled and legacy hashes purged.
pub trait LegacyHashVerifier: Send + Sync {
    /// Verify a password against a legacy hash.
    ///
    /// Returns `Ok(true)` if password matches, `Ok(false)` if not.
    /// Returns `Err` if the hash format is invalid or verification fails.
    fn verify(&self, password: &[u8], hash: &str) -> Result<bool, HashError>;

    /// Hash algorithm identifier (e.g., "bcrypt", "pbkdf2-sha256", "argon2id").
    fn algorithm(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_error_display() {
        let e = HashError::InvalidFormat("bad hash".into());
        assert_eq!(e.to_string(), "invalid hash format: bad hash");

        let e = HashError::CryptoError("hmac failed".into());
        assert_eq!(e.to_string(), "crypto error: hmac failed");

        let e = HashError::UnsupportedAlgorithm("scrypt".into());
        assert_eq!(e.to_string(), "unsupported algorithm: scrypt");
    }
}
