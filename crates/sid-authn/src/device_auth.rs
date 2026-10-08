// SPDX-License-Identifier: AGPL-3.0-only
//! Device Authorization Grant (RFC 8628).
//!
//! Implements the server-side logic for the device authorization flow:
//! 1. Device requests authorization → receives device_code + user_code
//! 2. User enters user_code on a separate device and authenticates
//! 3. Device polls with device_code until authorized/denied/expired

use sha2::{Digest, Sha256};
use sid_core::models::{DeviceAuthStatus, DeviceAuthorizationCode};

/// Errors from device authorization operations.
#[derive(Debug, thiserror::Error)]
pub enum DeviceAuthError {
    #[error("invalid client_id")]
    InvalidClient,

    #[error("user code not found or expired")]
    UserCodeNotFound,

    #[error("device code not found")]
    DeviceCodeNotFound,

    #[error("authorization pending")]
    AuthorizationPending,

    #[error("polling too fast (slow down)")]
    SlowDown,

    #[error("device code expired")]
    ExpiredToken,

    #[error("access denied by user")]
    AccessDenied,

    #[error("device code already exchanged")]
    AlreadyRedeemed,

    #[error("storage error: {0}")]
    Storage(#[from] sid_core::Error),
}

/// RFC 8628 error codes for the token endpoint.
impl DeviceAuthError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidClient => "invalid_client",
            Self::UserCodeNotFound => "invalid_grant",
            Self::DeviceCodeNotFound => "invalid_grant",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::AccessDenied => "access_denied",
            Self::AlreadyRedeemed => "invalid_grant",
            Self::Storage(_) => "server_error",
        }
    }
}

/// Characters used for user code generation (RFC 8628 §6.1).
/// Uses BCDFGHJKLMNPQRSTVWXZ — consonants only, no vowels to avoid
/// forming offensive words, no ambiguous characters (0/O, 1/I/L).
const USER_CODE_CHARS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Generate a human-readable user code (e.g., "WDJB-MJHT").
///
/// Format: 4 chars + hyphen + 4 chars = 8 effective characters.
/// Entropy: 20^8 ≈ 25.6 billion combinations.
pub fn generate_user_code() -> String {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let chars: Vec<u8> = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..USER_CODE_CHARS.len());
            USER_CODE_CHARS[idx]
        })
        .collect();

    format!(
        "{}-{}",
        std::str::from_utf8(&chars[..4]).unwrap(),
        std::str::from_utf8(&chars[4..]).unwrap(),
    )
}

/// Generate a cryptographically random device code (opaque token).
///
/// Returns (raw_code, sha256_hash) — raw code is sent to device,
/// hash is stored in database.
pub fn generate_device_code() -> (String, Vec<u8>) {
    use base64::Engine;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hash = Sha256::digest(raw.as_bytes()).to_vec();
    (raw, hash)
}

/// Hash a device code for lookup.
pub fn hash_device_code(device_code: &str) -> Vec<u8> {
    Sha256::digest(device_code.as_bytes()).to_vec()
}

/// Normalize a user code: uppercase, remove hyphens/spaces.
pub fn normalize_user_code(code: &str) -> String {
    code.to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect()
}

/// Validate the polling result for a device authorization request.
///
/// Called when a device polls with its device_code.
/// Returns Ok(()) if authorized, or appropriate error.
pub fn validate_poll(auth: &DeviceAuthorizationCode) -> Result<(), DeviceAuthError> {
    // Check expiry first
    if auth.is_expired() {
        return Err(DeviceAuthError::ExpiredToken);
    }

    match auth.status {
        DeviceAuthStatus::Pending => Err(DeviceAuthError::AuthorizationPending),
        DeviceAuthStatus::Authorized => Ok(()),
        DeviceAuthStatus::Denied => Err(DeviceAuthError::AccessDenied),
        DeviceAuthStatus::Expired => Err(DeviceAuthError::ExpiredToken),
        DeviceAuthStatus::Redeemed => Err(DeviceAuthError::AlreadyRedeemed),
    }
}

/// Build the verification_uri_complete with embedded user code.
///
/// Per RFC 8628 §3.2: verification_uri_complete includes the user code
/// so QR scanning doesn't require manual entry.
pub fn build_verification_uri_complete(verification_uri: &str, user_code: &str) -> String {
    format!("{}?code={}", verification_uri, user_code)
}

#[cfg(test)]
mod tests;
