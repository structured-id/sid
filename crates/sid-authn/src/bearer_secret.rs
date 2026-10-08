// SPDX-License-Identifier: AGPL-3.0-only
//! High-entropy bearer secrets SID issues to non-human callers (machine user
//! client secrets, provisioning connector credentials): shown once, stored
//! only as a verifier.
//!
//! A secret is a fixed prefix naming its kind followed by 32 random bytes in
//! unpadded base64url. With 256 bits of entropy a SHA-256 digest is a safe
//! verifier and a safe lookup key; no slow password hash is needed (NIST SP
//! 800-63B §5.1.1.2 asks for one only for memorized secrets).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore as _;
use secrecy::SecretBox;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// A newly issued secret and the verifier to store in its place.
pub struct IssuedSecret {
    /// The secret, handed to its holder once and never stored.
    pub secret: SecretBox<String>,
    /// SHA-256 of the secret, lowercase hex: what storage keeps and looks up.
    pub verifier: String,
}

/// Issue a fresh secret starting with `prefix`.
pub fn issue(prefix: &str) -> IssuedSecret {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let secret = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes));
    let verifier = verifier_of(&secret);
    IssuedSecret {
        secret: SecretBox::new(Box::new(secret)),
        verifier,
    }
}

/// The verifier of a presented secret.
pub fn verifier_of(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Whether `secret` is the one `verifier` was made from, compared in
/// constant time.
pub fn matches(secret: &str, verifier: &str) -> bool {
    verifier_of(secret)
        .as_bytes()
        .ct_eq(verifier.as_bytes())
        .into()
}

/// Whether `presented` has the form of a secret issued with `prefix`: the
/// prefix followed by a body. Says nothing about whether it is valid.
pub fn has_prefix(presented: &str, prefix: &str) -> bool {
    presented.len() > prefix.len() && presented.starts_with(prefix)
}

#[cfg(test)]
mod tests;
