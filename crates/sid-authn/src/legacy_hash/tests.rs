use super::*;

#[test]
fn test_bcrypt_verify_valid() {
    // Hash of "password123" with bcrypt cost 4
    let hash = bcrypt::hash("password123", 4).expect("bcrypt hash");
    let result = BuiltinLegacyVerifier::verify(b"password123", &hash);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_bcrypt_verify_invalid() {
    let hash = bcrypt::hash("password123", 4).expect("bcrypt hash");
    let result = BuiltinLegacyVerifier::verify(b"wrongpassword", &hash);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

/// A PHC argon2 hash of `password` with a fresh salt, as an importer stores it.
fn argon2_hash(password: &[u8]) -> String {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHasher, phc::PasswordHash};

    PasswordHasher::<PasswordHash>::hash_password(&Argon2::default(), password)
        .expect("argon2 hash")
        .to_string()
}

#[test]
fn test_argon2_verify_valid() {
    let hash = argon2_hash(b"secretpass");

    let result = BuiltinLegacyVerifier::verify(b"secretpass", &hash);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_argon2_verify_invalid() {
    let hash = argon2_hash(b"secretpass");

    let result = BuiltinLegacyVerifier::verify(b"wrongpass", &hash);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_unsupported_algorithm() {
    let result = BuiltinLegacyVerifier::verify(b"password", "$scrypt$n=16384$...");
    assert!(matches!(result, Err(HashError::UnsupportedAlgorithm(_))));
}

#[test]
fn test_detect_algorithm() {
    assert_eq!(
        BuiltinLegacyVerifier::detect_algorithm("$2b$12$abc"),
        Some("bcrypt")
    );
    assert_eq!(
        BuiltinLegacyVerifier::detect_algorithm("$2a$10$xyz"),
        Some("bcrypt")
    );
    assert_eq!(
        BuiltinLegacyVerifier::detect_algorithm("$argon2id$v=19$m=65536"),
        Some("argon2id")
    );
    assert_eq!(
        BuiltinLegacyVerifier::detect_algorithm("$argon2i$v=19$m=4096"),
        Some("argon2i")
    );
    assert_eq!(
        BuiltinLegacyVerifier::detect_algorithm("$pbkdf2-sha256$29000$..."),
        Some("pbkdf2-sha256")
    );
    assert_eq!(BuiltinLegacyVerifier::detect_algorithm("plaintext"), None);
}

#[test]
fn test_invalid_bcrypt_hash() {
    let result = BuiltinLegacyVerifier::verify(b"password", "$2b$notavalidhash");
    assert!(result.is_err());
}

#[test]
fn test_argon2_wrong_password_returns_false() {
    // "$argon2id$" prefix but wrong password → verification produces Ok(false)
    let hash = argon2_hash(b"correct");

    let result = BuiltinLegacyVerifier::verify(b"wrong", &hash);
    assert!(!result.unwrap());
}

/// The decoy spends a real bcrypt verification: it takes at least as long
/// as verifying a cost-4 hash, so an account without a legacy hash is not
/// answered noticeably faster than a wrong password.
#[test]
fn test_verify_decoy_spends_a_bcrypt_verification() {
    let hash = bcrypt::hash("password123", 4).expect("bcrypt hash");
    let started = std::time::Instant::now();
    BuiltinLegacyVerifier::verify(b"password123", &hash).unwrap();
    let cost_4 = started.elapsed();

    let started = std::time::Instant::now();
    BuiltinLegacyVerifier::verify_decoy(b"password123");
    assert!(
        started.elapsed() > cost_4,
        "cost 10 takes longer than cost 4"
    );
}
