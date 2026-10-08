use crate::primitives::AwsLcPrimitives;
use sid_keys::CryptoPrimitives;

fn crypto() -> AwsLcPrimitives {
    AwsLcPrimitives::new()
}

#[test]
fn test_aes_gcm_roundtrip() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce();
    let ct = c
        .aes_256_gcm_encrypt(&key, &nonce, b"hello", b"aad")
        .unwrap();
    let pt = c.aes_256_gcm_decrypt(&key, &nonce, &ct, b"aad").unwrap();
    assert_eq!(pt, b"hello");
}

#[test]
fn test_aes_gcm_aad_mismatch() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce();
    let ct = c
        .aes_256_gcm_encrypt(&key, &nonce, b"secret", b"aad-1")
        .unwrap();
    assert!(c.aes_256_gcm_decrypt(&key, &nonce, &ct, b"aad-2").is_err());
}

#[test]
fn test_hmac_sha256_rfc4231() {
    let c = crypto();
    let expected: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
        0x38, 0x43,
    ];
    assert_eq!(
        c.hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
        expected
    );
}

#[test]
fn test_hkdf_sha256_rfc5869() {
    let c = crypto();
    let ikm = [0x0bu8; 22];
    let salt: [u8; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let okm = c.hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
    assert_eq!(okm[0], 0x3c);
    assert_eq!(okm[41], 0x65);
}

#[test]
fn test_sha256_empty() {
    let c = crypto();
    let expected: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(c.sha256(b""), expected);
}

#[test]
fn test_provider_id() {
    assert_eq!(crypto().provider_id(), "aws-lc-rs");
}

#[test]
fn test_is_fips_matches_feature() {
    let c = crypto();
    assert_eq!(c.is_fips(), cfg!(feature = "fips"));
}

#[test]
fn test_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AwsLcPrimitives>();
}

// -- Wire compatibility: encrypt with one backend, decrypt with the other --

#[test]
fn test_wire_compat_aes_gcm() {
    use sid_keys::RustCryptoPrimitives;

    let aws = AwsLcPrimitives::new();
    let rc = RustCryptoPrimitives::new();
    let key = [42u8; 32];
    let aad = b"compat";

    // aws → rc
    let nonce = aws.random_nonce();
    let ct = aws
        .aes_256_gcm_encrypt(&key, &nonce, b"cross", aad)
        .unwrap();
    let pt = rc.aes_256_gcm_decrypt(&key, &nonce, &ct, aad).unwrap();
    assert_eq!(pt, b"cross");

    // rc → aws
    let nonce2 = rc.random_nonce();
    let ct2 = rc.aes_256_gcm_encrypt(&key, &nonce2, b"back", aad).unwrap();
    let pt2 = aws.aes_256_gcm_decrypt(&key, &nonce2, &ct2, aad).unwrap();
    assert_eq!(pt2, b"back");
}

#[test]
fn test_wire_compat_hmac() {
    use sid_keys::RustCryptoPrimitives;
    let aws = AwsLcPrimitives::new();
    let rc = RustCryptoPrimitives::new();
    assert_eq!(
        aws.hmac_sha256(&[1u8; 32], b"data"),
        rc.hmac_sha256(&[1u8; 32], b"data")
    );
}

#[test]
fn test_wire_compat_sha256() {
    use sid_keys::RustCryptoPrimitives;
    let aws = AwsLcPrimitives::new();
    let rc = RustCryptoPrimitives::new();
    assert_eq!(aws.sha256(b"test"), rc.sha256(b"test"));
}

#[test]
fn test_wire_compat_hkdf() {
    use sid_keys::RustCryptoPrimitives;
    let aws = AwsLcPrimitives::new();
    let rc = RustCryptoPrimitives::new();
    assert_eq!(
        aws.hkdf_sha256(b"ikm", b"salt", b"info", 32).unwrap(),
        rc.hkdf_sha256(b"ikm", b"salt", b"info", 32).unwrap()
    );
}

#[test]
fn test_wire_compat_pbkdf2() {
    use sid_keys::RustCryptoPrimitives;
    let aws = AwsLcPrimitives::new();
    let rc = RustCryptoPrimitives::new();

    let mut from_aws = [0u8; 32];
    let mut from_rc = [0u8; 32];
    aws.pbkdf2_sha256(b"password", b"salt", 1000, &mut from_aws)
        .unwrap();
    rc.pbkdf2_sha256(b"password", b"salt", 1000, &mut from_rc)
        .unwrap();
    assert_eq!(from_aws, from_rc);
}
