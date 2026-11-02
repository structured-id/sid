// SPDX-License-Identifier: AGPL-3.0-only
//! PBKDF2-HMAC KSF implementations for FIPS cipher suites.
//!
//! FIPS 800-132 requires minimum 1,000 iterations.
//! SID uses 600,000 iterations (conservative for OPAQUE context:
//! server never sees password — only OPRF output).

use hybrid_array::{Array, ArraySize};
use sid_opaque_ke::errors::InternalError;
use sid_opaque_ke::ksf::Ksf;

/// Default iteration count for PBKDF2 in OPAQUE context.
/// FIPS 800-132 minimum: 1,000. OWASP recommendation: 600,000 for SHA-256.
const PBKDF2_ITERATIONS: u32 = 600_000;

/// Fixed salt for PBKDF2 in OPAQUE KSF context.
/// In OPAQUE the KSF input is already the OPRF output (randomized),
/// so the salt provides domain separation, not entropy.
const PBKDF2_SALT: &[u8] = b"sid-opaque-ksf";

/// PBKDF2-HMAC-SHA256 KSF for P-256 FIPS cipher suite.
///
/// The iteration count is a field rather than a constant so that a test can
/// exercise the logic without paying the deliberate cost: 600,000 iterations
/// is the point of the function in production and a stall in an unoptimized
/// test build. `Default` is the production cost, and that is the only
/// constructor the cipher suite uses, so deployments are unaffected.
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2HmacSha256 {
    iterations: u32,
}

impl Default for Pbkdf2HmacSha256 {
    fn default() -> Self {
        Self {
            iterations: PBKDF2_ITERATIONS,
        }
    }
}

impl Ksf for Pbkdf2HmacSha256 {
    fn hash<L: ArraySize>(&self, input: Array<u8, L>) -> Result<Array<u8, L>, InternalError> {
        let mut output = Array::default();
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&input, PBKDF2_SALT, self.iterations, &mut output);
        Ok(output)
    }
}

/// PBKDF2-HMAC-SHA384 KSF for P-384 FIPS cipher suite.
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2HmacSha384 {
    iterations: u32,
}

impl Default for Pbkdf2HmacSha384 {
    fn default() -> Self {
        Self {
            iterations: PBKDF2_ITERATIONS,
        }
    }
}

impl Ksf for Pbkdf2HmacSha384 {
    fn hash<L: ArraySize>(&self, input: Array<u8, L>) -> Result<Array<u8, L>, InternalError> {
        let mut output = Array::default();
        pbkdf2::pbkdf2_hmac::<sha2::Sha384>(&input, PBKDF2_SALT, self.iterations, &mut output);
        Ok(output)
    }
}

/// PBKDF2-HMAC-SHA512 KSF for P-521 FIPS cipher suite.
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2HmacSha512 {
    iterations: u32,
}

impl Default for Pbkdf2HmacSha512 {
    fn default() -> Self {
        Self {
            iterations: PBKDF2_ITERATIONS,
        }
    }
}

impl Ksf for Pbkdf2HmacSha512 {
    fn hash<L: ArraySize>(&self, input: Array<u8, L>) -> Result<Array<u8, L>, InternalError> {
        let mut output = Array::default();
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&input, PBKDF2_SALT, self.iterations, &mut output);
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
