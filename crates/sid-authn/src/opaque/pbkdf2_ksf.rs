// SPDX-License-Identifier: AGPL-3.0-only
//! PBKDF2-HMAC KSF implementations for FIPS cipher suites.
//!
//! FIPS 800-132 requires minimum 1,000 iterations.
//! SID uses 600,000 iterations (conservative for OPAQUE context:
//! server never sees password — only OPRF output).

// opaque-ke's `Ksf` trait is written in terms of `generic_array` 0.14, which has
// deprecated its own types in favour of hybrid-array. The signatures below are
// the trait's, so the deprecated names are what an implementation must use until
// opaque-ke moves.
#![allow(deprecated)]

use generic_array::{ArrayLength, GenericArray};
use opaque_ke::errors::InternalError;
use opaque_ke::ksf::Ksf;

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
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
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
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
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
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&input, PBKDF2_SALT, self.iterations, &mut output);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_array::typenum::U32;

    /// Enough iterations to be the same function, few enough that an
    /// unoptimized build runs it in milliseconds. What these tests check —
    /// determinism, sensitivity to the input, separation between the three
    /// hashes — does not depend on the count.
    const CHEAP: u32 = 16;

    fn sha256() -> Pbkdf2HmacSha256 {
        Pbkdf2HmacSha256 { iterations: CHEAP }
    }
    fn sha384() -> Pbkdf2HmacSha384 {
        Pbkdf2HmacSha384 { iterations: CHEAP }
    }
    fn sha512() -> Pbkdf2HmacSha512 {
        Pbkdf2HmacSha512 { iterations: CHEAP }
    }

    #[test]
    fn test_pbkdf2_sha256_deterministic() {
        let ksf = sha256();
        let input: GenericArray<u8, U32> = GenericArray::clone_from_slice(&[42u8; 32]);
        let out1 = ksf.hash(input).unwrap();
        let out2 = ksf.hash(input).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_pbkdf2_sha256_different_inputs() {
        let ksf = sha256();
        let input1: GenericArray<u8, U32> = GenericArray::clone_from_slice(&[1u8; 32]);
        let input2: GenericArray<u8, U32> = GenericArray::clone_from_slice(&[2u8; 32]);
        let out1 = ksf.hash(input1).unwrap();
        let out2 = ksf.hash(input2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_pbkdf2_sha384_works() {
        let input: GenericArray<u8, U32> = GenericArray::clone_from_slice(&[7u8; 32]);
        let output = sha384().hash(input).unwrap();
        assert_ne!(output, GenericArray::default());
    }

    #[test]
    fn test_pbkdf2_sha512_works() {
        let input: GenericArray<u8, U32> = GenericArray::clone_from_slice(&[7u8; 32]);
        let output = sha512().hash(input).unwrap();
        assert_ne!(output, GenericArray::default());
    }

    #[test]
    fn test_all_ksf_produce_different_outputs() {
        let input: GenericArray<u8, U32> = GenericArray::clone_from_slice(&[99u8; 32]);
        let a = sha256().hash(input).unwrap();
        let b = sha384().hash(input).unwrap();
        let c = sha512().hash(input).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// The cost is the point of a KSF, so the number deployments actually run
    /// is asserted rather than assumed. Changing it changes every credential
    /// derived with it, since the client and the server must stretch alike.
    #[test]
    fn test_the_shipped_cost_is_the_configured_one() {
        // A const block: the floor is a property of the constant, so the
        // build is the right place to refuse a value below it.
        const _: () = assert!(
            PBKDF2_ITERATIONS >= 1_000,
            "FIPS 800-132 requires at least 1,000 iterations"
        );
        assert_eq!(PBKDF2_ITERATIONS, 600_000, "OWASP guidance for SHA-256");
        assert_eq!(Pbkdf2HmacSha256::default().iterations, PBKDF2_ITERATIONS);
        assert_eq!(Pbkdf2HmacSha384::default().iterations, PBKDF2_ITERATIONS);
        assert_eq!(Pbkdf2HmacSha512::default().iterations, PBKDF2_ITERATIONS);
    }

    #[test]
    fn test_default_trait() {
        let _: Pbkdf2HmacSha256 = Default::default();
        let _: Pbkdf2HmacSha384 = Default::default();
        let _: Pbkdf2HmacSha512 = Default::default();
    }
}
