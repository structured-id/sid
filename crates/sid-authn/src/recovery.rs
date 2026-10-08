// SPDX-License-Identifier: AGPL-3.0-only
//! Recovery codes: CE built-in fallback MFA, 10 one-time codes for emergency
//! account access. Recovery codes are NOT considered a security factor for
//! policy purposes (classified as `PhishingResistance::Fallback`).

use rand::Rng;
use sha2::{Digest, Sha256};

/// Number of recovery codes generated per set.
const RECOVERY_CODE_COUNT: usize = 10;

/// Each code is 8 alphanumeric characters in groups of 4 (e.g., "ABCD-1234").
const CODE_GROUP_LENGTH: usize = 4;

/// Characters used for recovery codes (unambiguous: no 0/O, 1/I/L).
const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Generate a set of recovery codes.
///
/// Returns (plaintext_codes, sha256_hashes).
pub fn generate_recovery_codes() -> (Vec<String>, Vec<String>) {
    let mut rng = rand::thread_rng();
    let mut plaintext = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut hashes = Vec::with_capacity(RECOVERY_CODE_COUNT);

    for _ in 0..RECOVERY_CODE_COUNT {
        let code = generate_single_code(&mut rng);
        let hash = hash_code(&code);
        plaintext.push(format_code(&code));
        hashes.push(hash);
    }

    (plaintext, hashes)
}

/// Generate a single 8-character recovery code.
fn generate_single_code(rng: &mut impl Rng) -> String {
    (0..CODE_GROUP_LENGTH * 2)
        .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

/// Format code with dash separator: "ABCD1234" → "ABCD-1234".
fn format_code(code: &str) -> String {
    if code.len() > CODE_GROUP_LENGTH {
        format!(
            "{}-{}",
            &code[..CODE_GROUP_LENGTH],
            &code[CODE_GROUP_LENGTH..]
        )
    } else {
        code.to_string()
    }
}

/// Normalize a code for comparison: uppercase, remove dashes/spaces.
pub fn normalize_code(code: &str) -> String {
    code.to_uppercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// SHA-256 hash a code (hex-encoded).
pub fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests;
