// SPDX-License-Identifier: Apache-2.0

use crate::{AwsLcPrimitives, CryptoPrimitives, RustCryptoPrimitives};

// Backend identity and module build remain explicit when both implementations are linked.
#[test]
fn aws_lc_identity_and_module_build_are_preserved() {
    let crypto = AwsLcPrimitives::new();
    assert_eq!(crypto.provider_id(), "aws-lc-rs");
    assert_eq!(crypto.is_fips(), cfg!(feature = "fips"));
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AwsLcPrimitives>();
}

// Ciphertext from either backend must decrypt through the other implementation.
#[test]
fn test_wire_compat_aes_gcm() {
    let aws = AwsLcPrimitives::new();
    let rc = RustCryptoPrimitives::new();
    let key = [42u8; 32];
    let aad = b"compat";

    let nonce = aws.random_nonce().unwrap();
    let ct = aws
        .aes_256_gcm_encrypt(&key, &nonce, b"cross", aad)
        .unwrap();
    let pt = rc.aes_256_gcm_decrypt(&key, &nonce, &ct, aad).unwrap();
    assert_eq!(pt, b"cross");

    let nonce2 = rc.random_nonce().unwrap();
    let ct2 = rc.aes_256_gcm_encrypt(&key, &nonce2, b"back", aad).unwrap();
    let pt2 = aws.aes_256_gcm_decrypt(&key, &nonce2, &ct2, aad).unwrap();
    assert_eq!(pt2, b"back");
}

// HMAC bytes remain independent of the selected implementation.
#[test]
fn test_wire_compat_hmac() {
    let aws = AwsLcPrimitives::new();
    let rc = RustCryptoPrimitives::new();
    assert_eq!(
        aws.hmac_sha256(&[1u8; 32], b"data"),
        rc.hmac_sha256(&[1u8; 32], b"data")
    );
}

// SHA-256 digest bytes remain interchangeable.
#[test]
fn test_wire_compat_sha256() {
    assert_eq!(
        AwsLcPrimitives::new().sha256(b"test"),
        RustCryptoPrimitives::new().sha256(b"test")
    );
}

// Stored derivation parameters reconstruct the same key through either backend.
#[test]
fn test_wire_compat_hkdf() {
    assert_eq!(
        AwsLcPrimitives::new()
            .hkdf_sha256(b"ikm", b"salt", b"info", 32)
            .unwrap(),
        RustCryptoPrimitives::new()
            .hkdf_sha256(b"ikm", b"salt", b"info", 32)
            .unwrap()
    );
}

// PBKDF2 does not change its derived bytes when the backend changes.
#[test]
fn test_wire_compat_pbkdf2() {
    let mut from_aws = [0u8; 32];
    let mut from_rc = [0u8; 32];
    AwsLcPrimitives::new()
        .pbkdf2_sha256(b"password", b"salt", 1000, &mut from_aws)
        .unwrap();
    RustCryptoPrimitives::new()
        .pbkdf2_sha256(b"password", b"salt", 1000, &mut from_rc)
        .unwrap();
    assert_eq!(from_aws, from_rc);
}
