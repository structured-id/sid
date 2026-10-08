// SPDX-License-Identifier: AGPL-3.0-only
//! TOTP (RFC 6238): codes, verification and replay refusal.
//!
//! HMAC-SHA1 with 6-digit codes and 30-second steps. Seeds are stored sealed
//! and read by the server; this module never holds one beyond a call.

use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use sid_core::models::{CredentialId, MfaEnrollment, MfaMethod, ProfileId};
use sid_plugin::cache::CacheBackend;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

/// TOTP parameters per RFC 6238.
pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_PERIOD: u64 = 30;
/// Allow +-1 time step for clock skew tolerance.
const TOTP_SKEW: u64 = 1;
/// Secret length in bytes (160 bits = 20 bytes, recommended by RFC 4226).
const SECRET_LENGTH: usize = 20;

/// Generate a random 20-byte TOTP secret.
pub fn generate_secret() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut secret = vec![0u8; SECRET_LENGTH];
    rng.fill(&mut secret[..]);
    secret
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

/// Generate the current valid TOTP code for a secret (for testing).
pub fn generate_current_totp(secret: &[u8]) -> String {
    let step = current_timestamp() / TOTP_PERIOD;
    compute_totp(secret, step)
}

/// Compute TOTP code for a given time step.
fn compute_totp(secret: &[u8], time_step: u64) -> String {
    let msg = time_step.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&msg);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (result[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    let otp = code % 10u32.pow(TOTP_DIGITS);
    format!("{:0>width$}", otp, width = TOTP_DIGITS as usize)
}

/// Verify a TOTP code with clock skew tolerance.
///
/// Uses constant-time comparison to prevent timing attacks that could
/// reveal which time window produces the correct code. Accepting a code
/// also takes a [`TotpReplayGuard`]: this function alone lets a code be used
/// again within its window.
pub fn verify_totp(secret: &[u8], code: &str) -> bool {
    totp_step(secret, code).is_some()
}

/// The time step whose code `code` is, within the clock skew tolerance.
///
/// Every window is evaluated and the matching step selected without
/// branching on the comparison, so the timing does not tell which window
/// matched.
pub fn totp_step(secret: &[u8], code: &str) -> Option<u64> {
    use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

    let current_step = current_timestamp() / TOTP_PERIOD;
    let mut found = Choice::from(0);
    let mut matched = 0u64;
    // Steps current - skew ..= current + skew; the time is past the epoch by
    // far more than one step, so the subtraction cannot wrap.
    for step in current_step - TOTP_SKEW..=current_step + TOTP_SKEW {
        let hit = compute_totp(secret, step).as_bytes().ct_eq(code.as_bytes());
        matched = u64::conditional_select(&matched, &step, hit);
        found |= hit;
    }
    bool::from(found).then_some(matched)
}

/// How long an accepted code stays recorded: past the last moment any
/// window still accepts it.
const TOTP_USED_TTL: Duration = Duration::from_secs(TOTP_PERIOD * (2 * TOTP_SKEW + 2));

/// Refuses a second use of an accepted TOTP code (RFC 6238 §5.2: the
/// verifier MUST NOT accept the second attempt of an OTP after it validated
/// the first). The record lives in the shared cache, so a code accepted by
/// one replica is refused by every other.
pub struct TotpReplayGuard {
    cache: Arc<dyn CacheBackend>,
}

impl TotpReplayGuard {
    pub fn new(cache: Arc<dyn CacheBackend>) -> Self {
        Self { cache }
    }

    /// Record the use of the code at `step` for `profile_id`. `false` when
    /// it was already used; an unreachable cache is an error, never a pass.
    pub async fn first_use(
        &self,
        profile_id: ProfileId,
        step: u64,
    ) -> sid_plugin::cache::CacheResult<bool> {
        self.cache
            .set_nx(
                &format!("totp:used:{profile_id}:{step}"),
                b"1",
                TOTP_USED_TTL,
            )
            .await
    }
}

/// Build an otpauth:// URI for QR code generation.
pub fn build_otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let secret_b32 = base32_encode(secret);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        issuer, account, secret_b32, issuer, TOTP_DIGITS, TOTP_PERIOD
    )
}

/// Base32 encode (RFC 4648, no padding).
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }

    if bits > 0 {
        buffer <<= 5 - bits;
        result.push(ALPHABET[(buffer & 0x1f) as usize] as char);
    }

    result
}

/// Base32 decode (RFC 4648, tolerates no-padding).
pub fn base32_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(encoded.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for ch in encoded.chars() {
        let val = match ch {
            'A'..='Z' => ch as u64 - 'A' as u64,
            '2'..='7' => ch as u64 - '2' as u64 + 26,
            'a'..='z' => ch as u64 - 'a' as u64, // case-insensitive
            '=' => continue,                     // skip padding
            _ => return None,
        };

        buffer = (buffer << 5) | val;
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            result.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    Some(result)
}

/// Validate and decode a base32-encoded TOTP seed from a legacy system.
///
/// Returns the raw bytes if the seed is valid base32 and has sufficient length
/// (minimum 16 bytes / 128 bits per RFC 4226 recommendation).
pub fn validate_totp_seed(base32_seed: &str) -> Result<Vec<u8>, TotpImportError> {
    let trimmed = base32_seed.trim();
    if trimmed.is_empty() {
        return Err(TotpImportError::EmptySeed);
    }

    let bytes = base32_decode(trimmed).ok_or(TotpImportError::InvalidBase32)?;

    // RFC 4226 recommends minimum 128 bits (16 bytes)
    if bytes.len() < 16 {
        return Err(TotpImportError::SeedTooShort {
            got: bytes.len(),
            min: 16,
        });
    }

    Ok(bytes)
}

/// Verify that a TOTP seed produces valid codes (import validation).
///
/// Generates a code from the seed and verifies it against itself — confirms
/// the seed is functional without needing user interaction.
pub fn verify_imported_totp_seed(seed_bytes: &[u8]) -> bool {
    let now = current_timestamp();
    let step = now / TOTP_PERIOD;
    let code = compute_totp(seed_bytes, step);
    verify_totp(seed_bytes, &code)
}

/// Import a TOTP seed from a legacy system and create an MfaEnrollment.
///
/// Validates the base32-encoded seed, verifies it produces valid codes,
/// and returns an Active enrollment. The seed bytes are returned separately
/// for storage as credential data (encrypted at rest by the storage layer).
pub fn import_totp_enrollment(
    profile_id: &ProfileId,
    base32_seed: &str,
) -> Result<(MfaEnrollment, Vec<u8>), TotpImportError> {
    let seed_bytes = validate_totp_seed(base32_seed)?;

    if !verify_imported_totp_seed(&seed_bytes) {
        return Err(TotpImportError::SeedSelfTestFailed);
    }

    let credential_id = CredentialId::new();
    let mut enrollment = MfaEnrollment::new(*profile_id, MfaMethod::Totp, credential_id);
    // Imported seeds are pre-verified — activate immediately
    enrollment.as_pending().unwrap().activate();

    Ok((enrollment, seed_bytes))
}

/// Error during TOTP seed import.
#[derive(Debug, thiserror::Error)]
pub enum TotpImportError {
    #[error("empty TOTP seed")]
    EmptySeed,
    #[error("invalid base32 encoding")]
    InvalidBase32,
    #[error("seed too short: {got} bytes, minimum {min} bytes")]
    SeedTooShort { got: usize, min: usize },
    #[error("TOTP seed self-test failed: seed does not produce valid codes")]
    SeedSelfTestFailed,
}

#[cfg(test)]
mod tests;
