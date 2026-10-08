// SPDX-License-Identifier: AGPL-3.0-only
//! Built-in legacy hash verifiers for password migration.
//!
//! Supports bcrypt, argon2id, and pbkdf2-sha256 — covering Keycloak, Auth0,
//! Okta, Zitadel, and Authentik hash formats.

use sid_plugin::legacy_hash::HashError;

/// Built-in verifier that auto-detects hash algorithm from the hash string format.
///
/// Supported formats:
/// - `$2a$`/`$2b$`/`$2y$` → bcrypt (Keycloak, Auth0)
/// - `$argon2id$`/`$argon2i$`/`$argon2d$` → argon2 (Authentik, Zitadel)
/// - `$pbkdf2-sha256$`/`$pbkdf2-sha512$` → pbkdf2 (Okta, Django)
pub struct BuiltinLegacyVerifier;

impl BuiltinLegacyVerifier {
    /// Verify a password against a legacy hash, auto-detecting the algorithm.
    pub fn verify(password: &[u8], hash: &str) -> Result<bool, HashError> {
        if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
            verify_bcrypt(password, hash)
        } else if hash.starts_with("$argon2") {
            verify_argon2(password, hash)
        } else if hash.starts_with("$pbkdf2") {
            verify_pbkdf2(password, hash)
        } else {
            Err(HashError::UnsupportedAlgorithm(format!(
                "unrecognized hash prefix: {}",
                hash.chars().take(10).collect::<String>()
            )))
        }
    }

    /// Spend the cost of one bcrypt verification (cost 10, the common cost
    /// of imported hashes) on a hash no password matches, so a migration
    /// attempt for an account without a legacy hash takes about as long as
    /// one with a wrong password.
    pub fn verify_decoy(password: &[u8]) {
        /// bcrypt hash (cost 10) of a value no account's password is.
        const DECOY: &str = "$2b$10$3S7AmXbLmGSgPqKzWGN3QutS1ENtPv1jcvMBMgXl2T/XRYGhPe2D.";
        // Only the time spent matters. A password that is not UTF-8 fails
        // before hashing here exactly as it does against a real bcrypt hash.
        let matched = verify_bcrypt(password, DECOY).unwrap_or(false);
        debug_assert!(!matched, "the decoy hash matched a password");
    }

    /// Detect the algorithm name from a hash string.
    pub fn detect_algorithm(hash: &str) -> Option<&'static str> {
        if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
            Some("bcrypt")
        } else if hash.starts_with("$argon2id$") {
            Some("argon2id")
        } else if hash.starts_with("$argon2i$") {
            Some("argon2i")
        } else if hash.starts_with("$argon2d$") {
            Some("argon2d")
        } else if hash.starts_with("$pbkdf2-sha256$") {
            Some("pbkdf2-sha256")
        } else if hash.starts_with("$pbkdf2-sha512$") {
            Some("pbkdf2-sha512")
        } else if hash.starts_with("$pbkdf2$") {
            Some("pbkdf2")
        } else {
            None
        }
    }
}

fn verify_bcrypt(password: &[u8], hash: &str) -> Result<bool, HashError> {
    // bcrypt crate expects &str password
    let password_str = std::str::from_utf8(password)
        .map_err(|e| HashError::InvalidFormat(format!("password is not valid UTF-8: {}", e)))?;
    bcrypt::verify(password_str, hash)
        .map_err(|e| HashError::CryptoError(format!("bcrypt verification failed: {}", e)))
}

fn verify_argon2(password: &[u8], hash: &str) -> Result<bool, HashError> {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    let parsed = PasswordHash::new(hash)
        .map_err(|e| HashError::InvalidFormat(format!("invalid argon2 hash: {}", e)))?;

    match Argon2::default().verify_password(password, &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(HashError::CryptoError(format!(
            "argon2 verification error: {}",
            e
        ))),
    }
}

fn verify_pbkdf2(password: &[u8], hash: &str) -> Result<bool, HashError> {
    use argon2::password_hash::PasswordHash;

    let parsed = PasswordHash::new(hash)
        .map_err(|e| HashError::InvalidFormat(format!("invalid pbkdf2 hash: {}", e)))?;

    // Extract parameters from the PHC string
    let salt = parsed
        .salt
        .ok_or_else(|| HashError::InvalidFormat("pbkdf2 hash missing salt".into()))?;
    let expected_hash = parsed
        .hash
        .ok_or_else(|| HashError::InvalidFormat("pbkdf2 hash missing hash output".into()))?;

    // Default to 29000 iterations (common for pbkdf2-sha256)
    let iterations = parsed
        .params
        .iter()
        .find(|(id, _)| id.as_str() == "i")
        .and_then(|(_, v)| v.decimal().ok())
        .unwrap_or(29000u32);

    // Compute PBKDF2-HMAC-SHA256 and compare
    let mut output = vec![0u8; expected_hash.len()];
    let salt_bytes = salt.as_str().as_bytes();
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt_bytes, iterations, &mut output);

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    let expected_bytes = expected_hash.as_bytes();
    Ok(output.ct_eq(expected_bytes).into())
}

#[cfg(test)]
mod tests;
