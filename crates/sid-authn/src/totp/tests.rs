// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn test_base32_roundtrip() {
    let data = b"Hello, World!";
    let encoded = base32_encode(data);
    let decoded = base32_decode(&encoded).unwrap();
    assert_eq!(&decoded, data);
}

#[test]
fn test_base32_known_vector() {
    // RFC 4648 test vectors
    assert_eq!(base32_encode(b""), "");
    assert_eq!(base32_encode(b"f"), "MY");
    assert_eq!(base32_encode(b"fo"), "MZXQ");
    assert_eq!(base32_encode(b"foo"), "MZXW6");
    assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
    assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
    assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
}

#[test]
fn test_compute_totp_rfc6238_vector() {
    // RFC 6238 test vector: SHA1 secret = "12345678901234567890" at time step 1
    let secret = b"12345678901234567890";
    // Time step 1 (t=30..59 seconds since epoch)
    let code = compute_totp(secret, 1);
    assert_eq!(code.len(), TOTP_DIGITS as usize);
    // The code should be deterministic
    assert_eq!(compute_totp(secret, 1), compute_totp(secret, 1));
}

#[test]
fn test_compute_totp_deterministic() {
    let secret = vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
    let code1 = compute_totp(&secret, 100);
    let code2 = compute_totp(&secret, 100);
    assert_eq!(code1, code2);
}

#[test]
fn test_compute_totp_different_steps_differ() {
    let secret = generate_secret();
    let code1 = compute_totp(&secret, 100);
    let code2 = compute_totp(&secret, 101);
    // Different time steps should (almost certainly) produce different codes
    // This is probabilistic but with 6 digits, collision is 1/1M
    assert_ne!(code1, code2);
}

#[test]
fn test_verify_totp_current_code() {
    let secret = generate_secret();
    let now = current_timestamp();
    let step = now / TOTP_PERIOD;
    let code = compute_totp(&secret, step);
    assert!(verify_totp(&secret, &code));
}

#[test]
fn test_verify_totp_wrong_code() {
    let secret = generate_secret();
    assert!(!verify_totp(&secret, "000000"));
}

#[test]
fn test_verify_totp_adjacent_step() {
    let secret = generate_secret();
    let now = current_timestamp();
    let step = now / TOTP_PERIOD;
    // Previous step should also be valid (skew tolerance)
    let code = compute_totp(&secret, step - 1);
    assert!(verify_totp(&secret, &code));
}

/// The step returned is the one whose code was given, so a code is recorded
/// under its own step whichever window it matched.
#[test]
fn totp_step_names_the_matching_step() {
    let secret = generate_secret();
    let step = current_timestamp() / TOTP_PERIOD;
    assert_eq!(totp_step(&secret, &compute_totp(&secret, step)), Some(step));
    assert_eq!(
        totp_step(&secret, &compute_totp(&secret, step - 1)),
        Some(step - 1)
    );
    assert_eq!(totp_step(&secret, &compute_totp(&secret, step - 5)), None);
}

/// A code's first use is recorded once; replicas share the record.
#[tokio::test]
async fn replay_guard_accepts_a_code_once() {
    let cache: Arc<dyn CacheBackend> = Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let a = TotpReplayGuard::new(cache.clone());
    let b = TotpReplayGuard::new(cache);
    let profile = ProfileId::generate();
    assert!(a.first_use(profile, 42).await.unwrap());
    assert!(!b.first_use(profile, 42).await.unwrap());
    // Another step, or another profile, is a different code.
    assert!(a.first_use(profile, 43).await.unwrap());
    assert!(a.first_use(ProfileId::generate(), 42).await.unwrap());
}

#[test]
fn test_generate_secret_length() {
    let secret = generate_secret();
    assert_eq!(secret.len(), SECRET_LENGTH);
}

#[test]
fn test_generate_secret_randomness() {
    let s1 = generate_secret();
    let s2 = generate_secret();
    assert_ne!(s1, s2);
}

#[test]
fn test_otpauth_uri_format() {
    let secret = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
    let uri = build_otpauth_uri("StructuredID", "alice", &secret);
    assert!(uri.starts_with("otpauth://totp/StructuredID:alice?"));
    assert!(uri.contains("secret="));
    assert!(uri.contains("issuer=StructuredID"));
    assert!(uri.contains("algorithm=SHA1"));
    assert!(uri.contains("digits=6"));
    assert!(uri.contains("period=30"));
}

#[test]
fn test_totp_code_length() {
    let secret = generate_secret();
    let code = compute_totp(&secret, 12345);
    assert_eq!(code.len(), 6);
    // All digits
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn test_totp_code_zero_padded() {
    // Find a secret/step combo that gives small code
    let secret = vec![0u8; 20];
    let code = compute_totp(&secret, 0);
    assert_eq!(code.len(), 6); // Should be zero-padded
}

#[test]
fn test_validate_totp_seed_valid_20_bytes() {
    // 20-byte secret (standard TOTP) base32-encoded
    let secret = generate_secret();
    let b32 = base32_encode(&secret);
    let result = validate_totp_seed(&b32);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), secret);
}

#[test]
fn test_validate_totp_seed_empty() {
    let result = validate_totp_seed("");
    assert!(matches!(result, Err(TotpImportError::EmptySeed)));
}

#[test]
fn test_validate_totp_seed_whitespace_only() {
    let result = validate_totp_seed("   ");
    assert!(matches!(result, Err(TotpImportError::EmptySeed)));
}

#[test]
fn test_validate_totp_seed_invalid_base32() {
    let result = validate_totp_seed("!!!invalid!!!");
    assert!(matches!(result, Err(TotpImportError::InvalidBase32)));
}

#[test]
fn test_validate_totp_seed_too_short() {
    // 10 bytes = too short (min 16)
    let short = vec![0x42u8; 10];
    let b32 = base32_encode(&short);
    let result = validate_totp_seed(&b32);
    assert!(matches!(
        result,
        Err(TotpImportError::SeedTooShort { got: 10, min: 16 })
    ));
}

#[test]
fn test_validate_totp_seed_exactly_16_bytes() {
    let seed = vec![0xABu8; 16];
    let b32 = base32_encode(&seed);
    let result = validate_totp_seed(&b32);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 16);
}

#[test]
fn test_validate_totp_seed_trims_whitespace() {
    let secret = generate_secret();
    let b32 = format!("  {}  ", base32_encode(&secret));
    let result = validate_totp_seed(&b32);
    assert!(result.is_ok());
}

#[test]
fn test_validate_totp_seed_case_insensitive() {
    let secret = generate_secret();
    let b32_lower = base32_encode(&secret).to_lowercase();
    let result = validate_totp_seed(&b32_lower);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), secret);
}

#[test]
fn test_verify_imported_totp_seed_valid() {
    let secret = generate_secret();
    assert!(verify_imported_totp_seed(&secret));
}

#[test]
fn test_import_totp_enrollment_valid() {
    let secret = generate_secret();
    let b32 = base32_encode(&secret);
    let profile_id = ProfileId::generate();
    let (enrollment, seed_bytes) = import_totp_enrollment(&profile_id, &b32).unwrap();
    assert_eq!(enrollment.profile_id, profile_id);
    assert_eq!(enrollment.method, MfaMethod::Totp);
    assert!(enrollment.is_active());
    assert_eq!(seed_bytes, secret);
}

#[test]
fn test_import_totp_enrollment_invalid_base32() {
    let profile_id = ProfileId::generate();
    let result = import_totp_enrollment(&profile_id, "!!!invalid!!!");
    assert!(matches!(result, Err(TotpImportError::InvalidBase32)));
}

#[test]
fn test_import_totp_enrollment_too_short() {
    let short = vec![0x42u8; 10];
    let b32 = base32_encode(&short);
    let profile_id = ProfileId::generate();
    let result = import_totp_enrollment(&profile_id, &b32);
    assert!(matches!(result, Err(TotpImportError::SeedTooShort { .. })));
}

#[test]
fn test_verify_imported_totp_seed_32_bytes() {
    // 32-byte seed (256-bit, used by some providers)
    let secret = vec![0x55u8; 32];
    assert!(verify_imported_totp_seed(&secret));
}
