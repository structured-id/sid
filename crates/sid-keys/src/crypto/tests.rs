use super::*;

fn crypto() -> RustCryptoPrimitives {
    RustCryptoPrimitives::new()
}

// -- AES-256-GCM --

#[test]
fn test_aes_gcm_encrypt_decrypt_roundtrip() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce();
    let plaintext = b"hello, world!";
    let aad = b"context:user-1";

    let ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext);

    let decrypted = c
        .aes_256_gcm_decrypt(&key, &nonce, &ciphertext, aad)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_aad_mismatch_fails() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce();

    let ciphertext = c
        .aes_256_gcm_encrypt(&key, &nonce, b"secret", b"aad-1")
        .unwrap();

    let result = c.aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"aad-2");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

#[test]
fn test_aes_gcm_wrong_key_fails() {
    let c = crypto();
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];
    let nonce = c.random_nonce();

    let ciphertext = c.aes_256_gcm_encrypt(&key1, &nonce, b"data", b"").unwrap();
    let result = c.aes_256_gcm_decrypt(&key2, &nonce, &ciphertext, b"");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

#[test]
fn test_aes_gcm_wrong_nonce_fails() {
    let c = crypto();
    let key = [7u8; 32];
    let nonce = c.random_nonce();
    let other_nonce = c.random_nonce();

    let ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, b"data", b"").unwrap();
    let result = c.aes_256_gcm_decrypt(&key, &other_nonce, &ciphertext, b"");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

#[test]
fn test_aes_gcm_truncated_ciphertext_fails() {
    let c = crypto();
    let key = [7u8; 32];
    let nonce = c.random_nonce();

    let mut ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, b"data", b"").unwrap();
    ciphertext.pop();

    let result = c.aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

#[test]
fn test_aes_gcm_flipped_tag_bit_fails() {
    let c = crypto();
    let key = [7u8; 32];
    let nonce = c.random_nonce();

    let mut ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, b"data", b"").unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    let result = c.aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

#[test]
fn test_aes_gcm_empty_plaintext() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce();

    let ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, b"", b"ctx").unwrap();
    let decrypted = c
        .aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"ctx")
        .unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_aes_gcm_large_payload() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce();
    let large = vec![0xABu8; 100_000];

    let ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, &large, b"").unwrap();
    let decrypted = c
        .aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"")
        .unwrap();
    assert_eq!(decrypted, large);
}

// -- HMAC-SHA256 (RFC 4231 Test Case 2) --

#[test]
fn test_hmac_sha256_rfc4231_case2() {
    let c = crypto();
    // RFC 4231 Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
        0x38, 0x43,
    ];
    assert_eq!(c.hmac_sha256(key, data), expected);
}

#[test]
fn test_hmac_sha256_deterministic() {
    let c = crypto();
    let key = [1u8; 32];
    let data = b"test data";
    let h1 = c.hmac_sha256(&key, data);
    let h2 = c.hmac_sha256(&key, data);
    assert_eq!(h1, h2);
}

#[test]
fn test_hmac_sha256_key_separation() {
    let c = crypto();
    let data = b"same message";
    assert_ne!(
        c.hmac_sha256(&[1u8; 32], data),
        c.hmac_sha256(&[2u8; 32], data)
    );
}

// -- HKDF-SHA256 (RFC 5869 Test Case 1) --

#[test]
fn test_hkdf_sha256_rfc5869_case1() {
    let c = crypto();
    let ikm = [0x0bu8; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    let okm = c.hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
    assert_eq!(okm.as_slice(), &expected);
}

#[test]
fn test_hkdf_sha256_output_length() {
    let c = crypto();
    let okm = c.hkdf_sha256(b"key", b"salt", b"info", 64).unwrap();
    assert_eq!(okm.len(), 64);
}

#[test]
fn test_hkdf_sha256_info_separation() {
    let c = crypto();
    // The `info` string is what separates one derived key from the next, so two
    // keys derived from one secret and salt must differ by it alone.
    let a = c.hkdf_sha256(b"ikm", b"salt", b"key-v1", 32).unwrap();
    let b = c.hkdf_sha256(b"ikm", b"salt", b"key-v2", 32).unwrap();
    assert_ne!(a, b);
}

#[test]
fn test_hkdf_sha256_salt_separation() {
    let c = crypto();
    let a = c.hkdf_sha256(b"ikm", b"salt-a", b"info", 32).unwrap();
    let b = c.hkdf_sha256(b"ikm", b"salt-b", b"info", 32).unwrap();
    assert_ne!(a, b);
}

#[test]
fn test_hkdf_sha256_rejects_oversized_output() {
    let c = crypto();
    // HKDF cannot expand beyond 255 * HashLen; SHA-256 gives 255 * 32 = 8160.
    let result = c.hkdf_sha256(b"ikm", b"salt", b"info", 8161);
    assert!(matches!(result, Err(CryptoError::KeyDerivation(_))));
}

// -- PBKDF2-HMAC-SHA256 --

#[test]
fn test_pbkdf2_sha256_known_answer() {
    let c = crypto();
    // Independently produced: hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 4096, 32)
    let expected: [u8; 32] = [
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c,
        0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98,
        0x13, 0x4a,
    ];
    let mut out = [0u8; 32];
    c.pbkdf2_sha256(b"password", b"salt", 4096, &mut out)
        .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn test_pbkdf2_sha256_iterations_change_output() {
    let c = crypto();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    c.pbkdf2_sha256(b"password", b"salt", 1000, &mut a).unwrap();
    c.pbkdf2_sha256(b"password", b"salt", 1001, &mut b).unwrap();
    assert_ne!(a, b);
}

#[test]
fn test_pbkdf2_sha256_fills_requested_length() {
    let c = crypto();
    let mut out = [0u8; 64];
    c.pbkdf2_sha256(b"password", b"salt", 100, &mut out)
        .unwrap();
    assert_ne!(out, [0u8; 64]);
}

// -- SHA-256 --

#[test]
fn test_sha256_empty() {
    let c = crypto();
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let expected: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(c.sha256(b""), expected);
}

#[test]
fn test_sha256_abc() {
    let c = crypto();
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(c.sha256(b"abc"), expected);
}

// -- Random --

#[test]
fn test_random_bytes_fills_buffer() {
    let c = crypto();
    let mut buf = [0u8; 32];
    c.random_bytes(&mut buf);
    // Probability of all zeros is 2^-256 — effectively impossible
    assert_ne!(buf, [0u8; 32]);
}

#[test]
fn test_random_bytes_empty_buffer_is_noop() {
    let c = crypto();
    let mut buf: [u8; 0] = [];
    c.random_bytes(&mut buf);
}

#[test]
fn test_random_nonce_unique() {
    let c = crypto();
    let n1 = c.random_nonce();
    let n2 = c.random_nonce();
    assert_ne!(n1, n2);
}

// -- Provider metadata --

#[test]
fn test_provider_id() {
    let c = crypto();
    assert_eq!(c.provider_id(), "rustcrypto");
}

#[test]
fn test_is_not_fips() {
    let c = crypto();
    assert!(!c.is_fips());
}

// -- Object safety --

#[test]
fn test_crypto_primitives_is_object_safe() {
    let c: Box<dyn CryptoPrimitives> = Box::new(RustCryptoPrimitives::new());
    let hash = c.sha256(b"test");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_crypto_primitives_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RustCryptoPrimitives>();
}
