// SPDX-License-Identifier: AGPL-3.0-only
//! Shamir's Secret Sharing over GF(256).
//!
//! Splits a secret byte slice into N shares with threshold M,
//! where any M shares can reconstruct the original secret,
//! but M-1 shares reveal zero information.
//!
//! Used for key recovery: data_key → 3 shards (threshold=2).

use rand::Rng;
use zeroize::Zeroize;

/// A single Shamir shard with its x-coordinate index and data.
#[derive(Clone)]
pub struct Shard {
    /// X-coordinate (1..=255, never 0). Identifies this shard.
    index: u8,
    /// Shard data — same length as the original secret.
    data: Vec<u8>,
}

impl Zeroize for Shard {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for Shard {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Shard {
    /// The x-coordinate index of this shard (1-based).
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The shard data bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume the shard and return (index, data).
    pub fn into_parts(mut self) -> (u8, Vec<u8>) {
        let data = std::mem::take(&mut self.data);
        let index = self.index;
        // data is moved out; Drop will zeroize the now-empty Vec (no-op)
        (index, data)
    }

    /// Reconstruct a shard from stored components.
    pub fn from_parts(index: u8, data: Vec<u8>) -> Result<Self, ShamirError> {
        if index == 0 {
            return Err(ShamirError::InvalidIndex);
        }
        Ok(Self { index, data })
    }
}

impl std::fmt::Debug for Shard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shard")
            .field("index", &self.index)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// Errors from Shamir operations.
#[derive(Debug, thiserror::Error)]
pub enum ShamirError {
    #[error("threshold must be >= 2")]
    ThresholdTooLow,
    #[error("total shares must be >= threshold")]
    NotEnoughShares,
    #[error("secret must not be empty")]
    EmptySecret,
    #[error("not enough shards to reconstruct (need at least 2, got {got})")]
    InsufficientShards { got: usize },
    #[error("shard index must be non-zero")]
    InvalidIndex,
    #[error("all shards must have the same data length")]
    InconsistentShardLength,
    #[error("duplicate shard indices")]
    DuplicateIndices,
}

/// Split a secret into `total` shards with `threshold` required to reconstruct.
///
/// Each byte of the secret is split independently using a random polynomial
/// of degree `threshold - 1` over GF(256).
///
/// # Arguments
/// * `secret` — the secret bytes to split (e.g., 32-byte AES key)
/// * `threshold` — minimum shards needed to reconstruct (must be >= 2)
/// * `total` — total shards to generate (must be >= threshold, <= 255)
///
/// # Returns
/// A vector of `total` shards, each with a unique index (1..=total).
pub fn split(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Shard>, ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::ThresholdTooLow);
    }
    if total < threshold {
        return Err(ShamirError::NotEnoughShares);
    }
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }

    let mut rng = rand::thread_rng();
    let mut shards: Vec<Shard> = (1..=total)
        .map(|i| Shard {
            index: i,
            data: vec![0u8; secret.len()],
        })
        .collect();

    // For each byte of the secret, create a random polynomial and evaluate
    // it at x=1, x=2, ..., x=total. The constant term is the secret byte.
    let mut coefficients = vec![0u8; threshold as usize];
    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        coefficients[0] = secret_byte;
        for coeff in coefficients.iter_mut().skip(1) {
            *coeff = rng.r#gen::<u8>();
        }

        for shard in shards.iter_mut() {
            shard.data[byte_idx] = gf256_eval_poly(&coefficients, shard.index);
        }
    }

    coefficients.zeroize();
    Ok(shards)
}

/// Reconstruct the secret from `threshold` or more shards.
///
/// Uses Lagrange interpolation over GF(256) to recover the constant term
/// of each byte's polynomial (which is the original secret byte).
pub fn reconstruct(shards: &[Shard]) -> Result<Vec<u8>, ShamirError> {
    if shards.len() < 2 {
        return Err(ShamirError::InsufficientShards { got: shards.len() });
    }

    let secret_len = shards[0].data.len();
    if secret_len == 0 {
        return Err(ShamirError::EmptySecret);
    }

    if shards.iter().any(|s| s.data.len() != secret_len) {
        return Err(ShamirError::InconsistentShardLength);
    }

    // Check for duplicate indices
    let mut seen = [false; 256];
    for shard in shards {
        if seen[shard.index as usize] {
            return Err(ShamirError::DuplicateIndices);
        }
        seen[shard.index as usize] = true;
    }

    // Lagrange interpolation at x=0 to recover each secret byte
    let mut secret = vec![0u8; secret_len];
    let xs: Vec<u8> = shards.iter().map(|s| s.index).collect();

    for (byte_idx, secret_byte) in secret.iter_mut().enumerate() {
        let ys: Vec<u8> = shards.iter().map(|s| s.data[byte_idx]).collect();
        *secret_byte = gf256_lagrange_at_zero(&xs, &ys);
    }

    Ok(secret)
}

// ── GF(256) arithmetic ──
//
// GF(256) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
// This is the AES (Rijndael) field. Generator element: 3.

/// GF(256) addition = XOR.
#[inline(always)]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(256) multiplication via log/exp tables.
#[inline]
fn gf256_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let log_a = LOG_TABLE[a as usize] as u16;
    let log_b = LOG_TABLE[b as usize] as u16;
    EXP_TABLE[((log_a + log_b) % 255) as usize]
}

/// GF(256) multiplicative inverse: a^(-1) = a^(254) = exp(255 - log(a)).
#[inline]
fn gf256_inv(a: u8) -> u8 {
    debug_assert_ne!(a, 0, "cannot invert zero in GF(256)");
    EXP_TABLE[(255 - LOG_TABLE[a as usize] as u16) as usize]
}

/// Evaluate polynomial at point x using Horner's method.
/// coefficients[0] = constant term, coefficients[d] = highest degree.
fn gf256_eval_poly(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &coeff in coefficients.iter().rev() {
        result = gf256_add(gf256_mul(result, x), coeff);
    }
    result
}

/// Lagrange interpolation at x=0.
/// Returns f(0) for the unique polynomial through points (xs[i], ys[i]).
fn gf256_lagrange_at_zero(xs: &[u8], ys: &[u8]) -> u8 {
    let n = xs.len();
    let mut result = 0u8;

    for i in 0..n {
        // Lagrange basis l_i(0) = product_{j!=i} x_j / (x_i ^ x_j)
        let mut basis = 1u8;
        for j in 0..n {
            if i == j {
                continue;
            }
            let num = xs[j];
            let den = gf256_add(xs[i], xs[j]);
            basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
        }
        result = gf256_add(result, gf256_mul(ys[i], basis));
    }

    result
}

// ── GF(256) log/exp lookup tables ──
//
// Generator: 3. Polynomial: 0x11B (x^8 + x^4 + x^3 + x + 1).
// EXP_TABLE[i] = 3^i mod P. LOG_TABLE[3^i] = i.

const fn generate_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];

    let mut val: u16 = 1;
    let mut i: usize = 0;
    while i < 255 {
        exp[i] = val as u8;
        log[val as usize] = i as u8;

        // Multiply by generator 3: val = val * 3 = val * 2 + val
        val = (val << 1) ^ val;
        if val >= 256 {
            val ^= 0x11B;
        }
        i += 1;
    }
    // Wrap-around entry for modular reduction convenience
    exp[255] = exp[0];

    (exp, log)
}

const TABLES: ([u8; 256], [u8; 256]) = generate_tables();
const EXP_TABLE: [u8; 256] = TABLES.0;
const LOG_TABLE: [u8; 256] = TABLES.1;

#[cfg(test)]
mod tests {
    use super::*;

    // ── GF(256) arithmetic tests ──

    #[test]
    fn gf256_add_is_xor() {
        assert_eq!(gf256_add(0, 0), 0);
        assert_eq!(gf256_add(0xFF, 0xFF), 0);
        assert_eq!(gf256_add(0xAB, 0x00), 0xAB);
        assert_eq!(gf256_add(0x53, 0xCA), 0x53 ^ 0xCA);
    }

    #[test]
    fn gf256_mul_identity_and_zero() {
        assert_eq!(gf256_mul(0, 42), 0);
        assert_eq!(gf256_mul(42, 0), 0);
        assert_eq!(gf256_mul(1, 42), 42);
        assert_eq!(gf256_mul(42, 1), 42);
    }

    #[test]
    fn gf256_mul_commutativity() {
        for a in [2u8, 3, 7, 100, 200, 255] {
            for b in [1u8, 2, 3, 50, 127, 254] {
                assert_eq!(gf256_mul(a, b), gf256_mul(b, a), "a={a}, b={b}");
            }
        }
    }

    #[test]
    fn gf256_inverse_roundtrip() {
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "a={a}, inv={inv}");
        }
    }

    #[test]
    fn gf256_exp_table_generator_3() {
        // 3^0 = 1, 3^1 = 3
        assert_eq!(EXP_TABLE[0], 1);
        assert_eq!(EXP_TABLE[1], 3);
        // All 255 non-zero elements are generated (exp table covers all)
        let mut seen = [false; 256];
        for i in 0..255 {
            seen[EXP_TABLE[i] as usize] = true;
        }
        // 0 is never generated (it's the additive identity)
        assert!(!seen[0]);
        // All 1..=255 are generated
        for v in 1..=255u8 {
            assert!(seen[v as usize], "value {v} not generated");
        }
    }

    // ── Polynomial evaluation tests ──

    #[test]
    fn eval_constant_polynomial() {
        // f(x) = 42
        assert_eq!(gf256_eval_poly(&[42], 0), 42);
        assert_eq!(gf256_eval_poly(&[42], 1), 42);
        assert_eq!(gf256_eval_poly(&[42], 255), 42);
    }

    #[test]
    fn eval_linear_polynomial_at_zero() {
        // f(x) = secret + a1*x, f(0) = secret
        assert_eq!(gf256_eval_poly(&[0xAB, 0x37], 0), 0xAB);
    }

    // ── Split/Reconstruct tests ──

    #[test]
    fn split_reconstruct_roundtrip_2_of_3() {
        let secret = b"this is a 32-byte secret key!!!";
        let shards = split(secret, 2, 3).unwrap();

        assert_eq!(shards.len(), 3);
        for shard in &shards {
            assert_eq!(shard.data().len(), secret.len());
        }

        // Any 2 of 3 reconstruct
        let recovered = reconstruct(&shards[0..2]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = reconstruct(&shards[1..3]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = reconstruct(&[shards[0].clone(), shards[2].clone()]).unwrap();
        assert_eq!(recovered, secret);

        // All 3 also reconstruct (over-determined)
        let recovered = reconstruct(&shards).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn split_reconstruct_roundtrip_3_of_5() {
        let secret = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let shards = split(&secret, 3, 5).unwrap();
        assert_eq!(shards.len(), 5);

        // Any 3 of 5
        let recovered = reconstruct(&shards[0..3]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = reconstruct(&shards[2..5]).unwrap();
        assert_eq!(recovered, secret);

        let recovered =
            reconstruct(&[shards[0].clone(), shards[2].clone(), shards[4].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn split_reconstruct_aes256_key() {
        // Real-world scenario: 32-byte AES-256 key
        let key: Vec<u8> = (0..32).collect();
        let shards = split(&key, 2, 3).unwrap();

        let recovered = reconstruct(&shards[0..2]).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn single_shard_reveals_nothing() {
        // Statistical test: single shard should look random
        let secret = vec![0u8; 32]; // all-zeros secret
        let shards = split(&secret, 2, 3).unwrap();

        // With a random polynomial, shards of an all-zero secret are NOT all-zero
        // (the random coefficient a1 makes f(x) = 0 + a1*x, so f(1)=a1, f(2)=2*a1, etc.)
        // At least one shard should be non-zero
        let any_nonzero = shards.iter().any(|s| s.data().iter().any(|&b| b != 0));
        assert!(any_nonzero, "shards of zero secret should not all be zero");
    }

    #[test]
    fn wrong_threshold_fails_reconstruction() {
        let secret = b"secret data here";
        let shards = split(secret, 3, 5).unwrap();

        // Only 2 shards (threshold is 3) — reconstruction gives wrong result
        let recovered = reconstruct(&shards[0..2]).unwrap();
        // The reconstruction succeeds mathematically (Lagrange works on any 2 points)
        // but the result is WRONG because the polynomial has degree 2, not 1
        assert_ne!(recovered.as_slice(), secret.as_slice());
    }

    #[test]
    fn threshold_equals_total() {
        let secret = b"all shards needed";
        let shards = split(secret, 3, 3).unwrap();

        // Need all 3
        let recovered = reconstruct(&shards).unwrap();
        assert_eq!(recovered, secret);

        // Only 2 gives wrong result
        let recovered = reconstruct(&shards[0..2]).unwrap();
        assert_ne!(recovered.as_slice(), secret.as_slice());
    }

    #[test]
    fn shard_order_does_not_matter() {
        let secret = b"order independence test";
        let shards = split(secret, 2, 3).unwrap();

        let r1 = reconstruct(&[shards[0].clone(), shards[1].clone()]).unwrap();
        let r2 = reconstruct(&[shards[1].clone(), shards[0].clone()]).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r1, secret);
    }

    #[test]
    fn single_byte_secret() {
        let secret = vec![0x42];
        let shards = split(&secret, 2, 3).unwrap();
        let recovered = reconstruct(&shards[0..2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn max_threshold_255_of_255() {
        let secret = vec![0xAB; 16];
        let shards = split(&secret, 255, 255).unwrap();
        assert_eq!(shards.len(), 255);

        let recovered = reconstruct(&shards).unwrap();
        assert_eq!(recovered, secret);
    }

    // ── Error handling tests ──

    #[test]
    fn split_threshold_too_low() {
        assert!(matches!(
            split(b"x", 1, 3),
            Err(ShamirError::ThresholdTooLow)
        ));
        assert!(matches!(
            split(b"x", 0, 3),
            Err(ShamirError::ThresholdTooLow)
        ));
    }

    #[test]
    fn split_not_enough_shares() {
        assert!(matches!(
            split(b"x", 5, 3),
            Err(ShamirError::NotEnoughShares)
        ));
    }

    #[test]
    fn split_empty_secret() {
        assert!(matches!(split(b"", 2, 3), Err(ShamirError::EmptySecret)));
    }

    #[test]
    fn reconstruct_insufficient_shards() {
        let shards = split(b"test", 2, 3).unwrap();
        assert!(matches!(
            reconstruct(&shards[0..1]),
            Err(ShamirError::InsufficientShards { .. })
        ));
        assert!(matches!(
            reconstruct(&[]),
            Err(ShamirError::InsufficientShards { .. })
        ));
    }

    #[test]
    fn reconstruct_duplicate_indices() {
        let shards = split(b"test", 2, 3).unwrap();
        let dup = vec![shards[0].clone(), shards[0].clone()];
        assert!(matches!(
            reconstruct(&dup),
            Err(ShamirError::DuplicateIndices)
        ));
    }

    #[test]
    fn reconstruct_inconsistent_length() {
        let s1 = Shard::from_parts(1, vec![1, 2, 3]).unwrap();
        let s2 = Shard::from_parts(2, vec![4, 5]).unwrap();
        assert!(matches!(
            reconstruct(&[s1, s2]),
            Err(ShamirError::InconsistentShardLength)
        ));
    }

    #[test]
    fn shard_from_parts_zero_index() {
        assert!(matches!(
            Shard::from_parts(0, vec![1]),
            Err(ShamirError::InvalidIndex)
        ));
    }

    #[test]
    fn shard_into_parts_roundtrip() {
        let shard = Shard::from_parts(5, vec![10, 20, 30]).unwrap();
        let (idx, data) = shard.into_parts();
        assert_eq!(idx, 5);
        assert_eq!(data, vec![10, 20, 30]);
    }

    #[test]
    fn shard_debug_does_not_leak_data() {
        let shard = Shard::from_parts(1, vec![0xDE, 0xAD]).unwrap();
        let debug = format!("{:?}", shard);
        assert!(debug.contains("data_len: 2"));
        assert!(!debug.contains("DE"));
        assert!(!debug.contains("AD"));
    }

    // ── Determinism tests ──

    #[test]
    fn different_splits_produce_different_shards() {
        let secret = b"determinism check";
        let s1 = split(secret, 2, 3).unwrap();
        let s2 = split(secret, 2, 3).unwrap();

        // Random coefficients mean shards differ (with overwhelming probability)
        let same = s1.iter().zip(s2.iter()).all(|(a, b)| a.data() == b.data());
        assert!(
            !same,
            "two independent splits should produce different shards"
        );

        // But both reconstruct to the same secret
        let r1 = reconstruct(&s1[0..2]).unwrap();
        let r2 = reconstruct(&s2[0..2]).unwrap();
        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
    }
}
