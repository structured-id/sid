// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn test_generate_single_code_length() {
    let mut rng = rand::rng();
    let code = generate_single_code(&mut rng);
    assert_eq!(code.len(), CODE_GROUP_LENGTH * 2);
}

#[test]
fn test_generate_single_code_alphabet() {
    let mut rng = rand::rng();
    for _ in 0..100 {
        let code = generate_single_code(&mut rng);
        for ch in code.chars() {
            assert!(
                CODE_ALPHABET.contains(&(ch as u8)),
                "unexpected character: {}",
                ch
            );
        }
    }
}

#[test]
fn test_generate_single_code_randomness() {
    let mut rng = rand::rng();
    let c1 = generate_single_code(&mut rng);
    let c2 = generate_single_code(&mut rng);
    // Extremely unlikely to be equal (30^8 ≈ 6.5×10^11 possibilities).
    assert_ne!(c1, c2);
}

#[test]
fn test_format_code() {
    assert_eq!(format_code("ABCD1234"), "ABCD-1234");
    assert_eq!(format_code("XY"), "XY");
}

#[test]
fn test_normalize_code() {
    assert_eq!(normalize_code("abcd-1234"), "ABCD1234");
    assert_eq!(normalize_code("  AB CD  12 34 "), "ABCD1234");
    assert_eq!(normalize_code("ABCD1234"), "ABCD1234");
}

#[test]
fn test_hash_code_deterministic() {
    let h1 = hash_code("ABCD1234");
    let h2 = hash_code("ABCD1234");
    assert_eq!(h1, h2);
}

#[test]
fn test_hash_code_different_inputs() {
    let h1 = hash_code("ABCD1234");
    let h2 = hash_code("WXYZ5678");
    assert_ne!(h1, h2);
}

#[test]
fn test_generate_recovery_codes_count() {
    let (plaintext, hashes) = generate_recovery_codes();
    assert_eq!(plaintext.len(), RECOVERY_CODE_COUNT);
    assert_eq!(hashes.len(), RECOVERY_CODE_COUNT);
}

#[test]
fn test_generate_recovery_codes_format() {
    let (plaintext, _) = generate_recovery_codes();
    for code in &plaintext {
        // Format: "XXXX-XXXX"
        assert_eq!(code.len(), CODE_GROUP_LENGTH * 2 + 1);
        assert_eq!(&code[CODE_GROUP_LENGTH..CODE_GROUP_LENGTH + 1], "-");
    }
}

#[test]
fn test_generate_recovery_codes_unique() {
    let (plaintext, hashes) = generate_recovery_codes();
    // All codes should be unique.
    let unique_codes: std::collections::HashSet<_> = plaintext.iter().collect();
    assert_eq!(unique_codes.len(), RECOVERY_CODE_COUNT);
    let unique_hashes: std::collections::HashSet<_> = hashes.iter().collect();
    assert_eq!(unique_hashes.len(), RECOVERY_CODE_COUNT);
}

#[test]
fn test_hash_matches_normalized_code() {
    let (plaintext, hashes) = generate_recovery_codes();
    for (code, hash) in plaintext.iter().zip(hashes.iter()) {
        let normalized = normalize_code(code);
        assert_eq!(&hash_code(&normalized), hash);
    }
}

#[test]
fn test_hash_case_insensitive_via_normalize() {
    let (plaintext, hashes) = generate_recovery_codes();
    for (code, hash) in plaintext.iter().zip(hashes.iter()) {
        let lower = code.to_lowercase();
        let normalized = normalize_code(&lower);
        assert_eq!(&hash_code(&normalized), hash);
    }
}
