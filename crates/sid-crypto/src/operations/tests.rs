use super::*;
use alloc::{boxed::Box, vec};

#[cfg(feature = "primitives")]
type Backend = crate::RustCryptoPrimitives;
#[cfg(all(not(feature = "primitives"), feature = "aws-lc"))]
type Backend = crate::AwsLcPrimitives;

fn crypto() -> Backend {
    Backend::new()
}

// RFC 8018 requires refusal before invalid iteration parameters alter output.
#[test]
fn pbkdf2_rejects_zero_iterations_before_writing() {
    let mut output = [0xa5; 32];
    assert!(
        crypto()
            .pbkdf2_sha256(b"password", b"salt", 0, &mut output)
            .is_err()
    );
    assert_eq!(output, [0xa5; 32]);
}

// The derived-key length is also a positive integer in RFC 8018 section 5.2.
#[test]
fn pbkdf2_rejects_empty_output() {
    assert!(
        crypto()
            .pbkdf2_sha256(b"password", b"salt", 1, &mut [])
            .is_err()
    );
}

// Excessive HKDF length is refused before attempting allocation.
#[test]
fn hkdf_rejects_impossible_length_before_allocation() {
    assert!(
        crypto()
            .hkdf_sha256(b"key", b"salt", b"info", usize::MAX)
            .is_err()
    );
}

// Encryption preserves the plaintext only after authenticated decryption.
#[test]
fn test_aes_gcm_encrypt_decrypt_roundtrip() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce().unwrap();
    let plaintext = b"hello, world!";
    let aad = b"context:user-1";
    let ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext);
    let decrypted = c
        .aes_256_gcm_decrypt(&key, &nonce, &ciphertext, aad)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

// A ciphertext cannot be moved into another authenticated context.
#[test]
fn test_aes_gcm_aad_mismatch_fails() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce().unwrap();
    let ciphertext = c
        .aes_256_gcm_encrypt(&key, &nonce, b"secret", b"aad-1")
        .unwrap();
    let result = c.aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"aad-2");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

// A different key cannot authenticate an otherwise intact ciphertext.
#[test]
fn test_aes_gcm_wrong_key_fails() {
    let c = crypto();
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];
    let nonce = c.random_nonce().unwrap();
    let ciphertext = c.aes_256_gcm_encrypt(&key1, &nonce, b"data", b"").unwrap();
    let result = c.aes_256_gcm_decrypt(&key2, &nonce, &ciphertext, b"");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

// The nonce participates in authentication, not just encryption.
#[test]
fn test_aes_gcm_wrong_nonce_fails() {
    let c = crypto();
    let key = [7u8; 32];
    let nonce = c.random_nonce().unwrap();
    let other_nonce = c.random_nonce().unwrap();
    let ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, b"data", b"").unwrap();
    let result = c.aes_256_gcm_decrypt(&key, &other_nonce, &ciphertext, b"");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

// Truncation never produces a partial successful plaintext.
#[test]
fn test_aes_gcm_truncated_ciphertext_fails() {
    let c = crypto();
    let key = [7u8; 32];
    let nonce = c.random_nonce().unwrap();
    let mut ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, b"data", b"").unwrap();
    ciphertext.pop();
    let result = c.aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

// A changed authentication tag is rejected.
#[test]
fn test_aes_gcm_flipped_tag_bit_fails() {
    let c = crypto();
    let key = [7u8; 32];
    let nonce = c.random_nonce().unwrap();
    let mut ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, b"data", b"").unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;
    let result = c.aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"");
    assert!(matches!(result, Err(CryptoError::Decryption(_))));
}

// Empty plaintext remains authenticated data with an intact tag.
#[test]
fn test_aes_gcm_empty_plaintext() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce().unwrap();
    let ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, b"", b"ctx").unwrap();
    let decrypted = c
        .aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"ctx")
        .unwrap();
    assert!(decrypted.is_empty());
}

// Large payloads preserve every byte across the same interface.
#[test]
fn test_aes_gcm_large_payload() {
    let c = crypto();
    let key = [42u8; 32];
    let nonce = c.random_nonce().unwrap();
    let large = vec![0xABu8; 100_000];
    let ciphertext = c.aes_256_gcm_encrypt(&key, &nonce, &large, b"").unwrap();
    let decrypted = c
        .aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"")
        .unwrap();
    assert_eq!(decrypted, large);
}

// RFC 4231 test case 2 supplies an independent full-width known answer.
#[test]
fn test_hmac_sha256_rfc4231_case2() {
    let c = crypto();
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
        0x38, 0x43,
    ];
    assert_eq!(c.hmac_sha256(key, data), expected);
}

// Repeated MAC calls do not consume or corrupt keyed state.
#[test]
fn test_hmac_sha256_deterministic() {
    let c = crypto();
    let key = [1u8; 32];
    let data = b"test data";
    let h1 = c.hmac_sha256(&key, data);
    let h2 = c.hmac_sha256(&key, data);
    assert_eq!(h1, h2);
}

// Independent keys must remain cryptographically separated.
#[test]
fn test_hmac_sha256_key_separation() {
    let c = crypto();
    let data = b"same message";
    assert_ne!(
        c.hmac_sha256(&[1u8; 32], data),
        c.hmac_sha256(&[2u8; 32], data)
    );
}

// RFC 5869 test case 1 checks the complete expanded key.
#[test]
fn test_hkdf_sha256_rfc5869_case1() {
    let c = crypto();
    let ikm = [0x0bu8; 22];
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    let okm = c.hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
    assert_eq!(okm.as_slice(), &expected);
}

// Successful expansion returns the exact requested length.
#[test]
fn test_hkdf_sha256_output_length() {
    let okm = crypto().hkdf_sha256(b"key", b"salt", b"info", 64).unwrap();
    assert_eq!(okm.len(), 64);
}

// Context labels separate otherwise identical key derivations.
#[test]
fn test_hkdf_sha256_info_separation() {
    let c = crypto();
    let a = c.hkdf_sha256(b"ikm", b"salt", b"key-v1", 32).unwrap();
    let b = c.hkdf_sha256(b"ikm", b"salt", b"key-v2", 32).unwrap();
    assert_ne!(a, b);
}

// Salt changes also separate the derived keys.
#[test]
fn test_hkdf_sha256_salt_separation() {
    let c = crypto();
    let a = c.hkdf_sha256(b"ikm", b"salt-a", b"info", 32).unwrap();
    let b = c.hkdf_sha256(b"ikm", b"salt-b", b"info", 32).unwrap();
    assert_ne!(a, b);
}

// The first byte beyond RFC 5869's expansion bound is rejected.
#[test]
fn test_hkdf_sha256_rejects_oversized_output() {
    let result = crypto().hkdf_sha256(b"ikm", b"salt", b"info", 8161);
    assert!(matches!(result, Err(CryptoError::KeyDerivation(_))));
}

// The maximum permitted expansion is accepted, not just ordinary short outputs.
#[test]
fn hkdf_accepts_the_exact_output_boundary() {
    assert_eq!(
        crypto()
            .hkdf_sha256(b"ikm", b"salt", b"info", 8160)
            .unwrap()
            .len(),
        8160
    );
}

// Independent hashlib.pbkdf2_hmac output checks PBKDF2 arithmetic.
#[test]
fn test_pbkdf2_sha256_known_answer() {
    let expected = [
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c,
        0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98,
        0x13, 0x4a,
    ];
    let mut output = [0; 32];
    crypto()
        .pbkdf2_sha256(b"password", b"salt", 4096, &mut output)
        .unwrap();
    assert_eq!(output, expected);
}

// Different positive iteration counts cannot silently collapse to one pass.
#[test]
fn test_pbkdf2_sha256_iterations_change_output() {
    let c = crypto();
    let mut a = [0; 32];
    let mut b = [0; 32];
    c.pbkdf2_sha256(b"password", b"salt", 1000, &mut a).unwrap();
    c.pbkdf2_sha256(b"password", b"salt", 1001, &mut b).unwrap();
    assert_ne!(a, b);
}

// Multi-block PBKDF2 fills the whole caller buffer.
#[test]
fn test_pbkdf2_sha256_fills_requested_length() {
    let mut output = [0; 64];
    crypto()
        .pbkdf2_sha256(b"password", b"salt", 100, &mut output)
        .unwrap();
    assert_ne!(output, [0; 64]);
}

// SHA-256's empty-message vector checks the full digest.
#[test]
fn test_sha256_empty() {
    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(crypto().sha256(b""), expected);
}

// A nonempty SHA-256 vector catches an incorrectly reset or truncated digest.
#[test]
fn test_sha256_abc() {
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(crypto().sha256(b"abc"), expected);
}

// Secure generation must fill rather than return a zero-initialized buffer.
#[test]
fn test_random_bytes_fills_buffer() {
    let mut bytes = [0; 32];
    crypto().random_bytes(&mut bytes).unwrap();
    assert_ne!(bytes, [0; 32]);
}

// Empty output is a valid RNG no-op, distinct from failed entropy.
#[test]
fn test_random_bytes_empty_buffer_is_noop() {
    crypto().random_bytes(&mut []).unwrap();
}

// Successive nonce requests must not reuse a fixed or cached nonce.
#[test]
fn test_random_nonce_unique() {
    let c = crypto();
    assert_ne!(c.random_nonce().unwrap(), c.random_nonce().unwrap());
}

// Diagnostics identify the selected implementation without changing policy.
#[test]
fn test_provider_id() {
    let expected = if cfg!(feature = "primitives") {
        "rustcrypto"
    } else {
        "aws-lc-rs"
    };
    assert_eq!(crypto().provider_id(), expected);
}

// A build-mode flag is reported only by its actual selected backend.
#[test]
fn test_selected_module_mode() {
    assert_eq!(
        crypto().is_fips(),
        cfg!(all(not(feature = "primitives"), feature = "fips"))
    );
}

// Existing key managers can use the common interface as a trait object.
#[test]
fn test_crypto_primitives_is_object_safe() {
    let c: Box<dyn CryptoPrimitives> = Box::new(Backend::new());
    assert_eq!(c.sha256(b"test").len(), 32);
}

// Stateless adapters retain the thread-safety required by host composition.
#[test]
fn test_crypto_primitives_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Backend>();
}
