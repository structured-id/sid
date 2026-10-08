use super::*;
use hybrid_array::typenum::U32;

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
    let input: Array<u8, U32> = Array::from([42u8; 32]);
    let out1 = ksf.hash(input).unwrap();
    let out2 = ksf.hash(input).unwrap();
    assert_eq!(out1, out2);
}

#[test]
fn test_pbkdf2_sha256_different_inputs() {
    let ksf = sha256();
    let input1: Array<u8, U32> = Array::from([1u8; 32]);
    let input2: Array<u8, U32> = Array::from([2u8; 32]);
    let out1 = ksf.hash(input1).unwrap();
    let out2 = ksf.hash(input2).unwrap();
    assert_ne!(out1, out2);
}

#[test]
fn test_pbkdf2_sha384_works() {
    let input: Array<u8, U32> = Array::from([7u8; 32]);
    let output = sha384().hash(input).unwrap();
    assert_ne!(output, Array::default());
}

#[test]
fn test_pbkdf2_sha512_works() {
    let input: Array<u8, U32> = Array::from([7u8; 32]);
    let output = sha512().hash(input).unwrap();
    assert_ne!(output, Array::default());
}

#[test]
fn test_all_ksf_produce_different_outputs() {
    let input: Array<u8, U32> = Array::from([99u8; 32]);
    let a = sha256().hash(input).unwrap();
    let b = sha384().hash(input).unwrap();
    let c = sha512().hash(input).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

/// The output is RFC 8018 PBKDF2-HMAC-SHA256 of the input under the fixed
/// salt, computed independently with the HMAC primitive: a stored credential
/// verifies only while the KSF stays this exact function.
#[test]
fn test_pbkdf2_sha256_is_rfc_8018() {
    use hmac::{Hmac, KeyInit, Mac};

    let input = [5u8; 32];
    let iterations = CHEAP;
    // RFC 8018 section 5.2, one 32-byte block: U_1 = PRF(P, S || INT(1)).
    let prf = || <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&input).unwrap();
    let mut u = prf()
        .chain_update(PBKDF2_SALT)
        .chain_update(1u32.to_be_bytes())
        .finalize()
        .into_bytes();
    let mut t = u;
    for _ in 1..iterations {
        u = prf().chain_update(u).finalize().into_bytes();
        for (t, u) in t.iter_mut().zip(u.iter()) {
            *t ^= u;
        }
    }

    let output = sha256().hash(Array::<u8, U32>::from(input)).unwrap();
    assert_eq!(output.as_slice(), t.as_slice());
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
