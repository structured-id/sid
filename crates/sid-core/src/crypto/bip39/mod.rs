// SPDX-License-Identifier: AGPL-3.0-only
//! BIP-39 mnemonic encoding/decoding for recovery seed phrases.
//!
//! Encodes 256-bit entropy as 24 English words with checksum.
//! Used for key recovery: mnemonic → PBKDF2 → HKDF → AES-256 recovery key.
//!
//! We use BIP-39 encoding ONLY (not BIP-32/44 HD derivation).

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

mod wordlist;

/// Errors from BIP-39 operations.
#[derive(Debug, thiserror::Error)]
pub enum Bip39Error {
    #[error("entropy must be exactly 32 bytes (256 bits)")]
    InvalidEntropyLength,
    #[error("mnemonic must be exactly 24 words")]
    InvalidWordCount,
    #[error("word not in BIP-39 wordlist: {0}")]
    UnknownWord(String),
    #[error("checksum mismatch (typo in recovery phrase?)")]
    ChecksumMismatch,
    #[error("the operating system random source is unavailable")]
    Entropy,
}

/// Encode 256-bit entropy as 24-word BIP-39 mnemonic.
///
/// Appends 8-bit SHA-256 checksum (first 8 bits of SHA-256(entropy)),
/// giving 264 bits total = 24 words × 11 bits each.
pub fn encode(entropy: &[u8; 32]) -> Result<Vec<String>, Bip39Error> {
    let checksum_byte = Sha256::digest(entropy)[0];

    // Build bool bitstream: 256 bits entropy + 8 bits checksum = 264 bits
    let mut bits = Vec::with_capacity(264);
    for &byte in entropy.iter() {
        for j in (0..8).rev() {
            bits.push((byte >> j) & 1 == 1);
        }
    }
    for j in (0..8).rev() {
        bits.push((checksum_byte >> j) & 1 == 1);
    }

    // Extract 24 words, each 11 bits
    let mut words = Vec::with_capacity(24);
    for i in 0..24 {
        let mut index: u16 = 0;
        for b in 0..11 {
            if bits[i * 11 + b] {
                index |= 1 << (10 - b);
            }
        }
        words.push(wordlist::WORDLIST[index as usize].to_string());
    }

    Ok(words)
}

/// Decode 24-word mnemonic back to 256-bit entropy.
/// Validates checksum.
pub fn decode(words: &[String]) -> Result<[u8; 32], Bip39Error> {
    if words.len() != 24 {
        return Err(Bip39Error::InvalidWordCount);
    }

    // Convert words to 11-bit indices
    let mut indices = Vec::with_capacity(24);
    for word in words {
        let lower = word.to_lowercase();
        let idx = wordlist::WORDLIST
            .iter()
            .position(|&w| w == lower)
            .ok_or_else(|| Bip39Error::UnknownWord(word.clone()))?;
        indices.push(idx as u16);
    }

    // Reconstruct 264 bits from indices
    let mut bits = Vec::with_capacity(264);
    for &idx in &indices {
        for b in (0..11).rev() {
            bits.push((idx >> b) & 1 == 1);
        }
    }

    // First 256 bits = entropy, last 8 bits = checksum
    let mut entropy = [0u8; 32];
    for (byte_idx, byte) in entropy.iter_mut().enumerate() {
        for bit in 0..8 {
            if bits[byte_idx * 8 + bit] {
                *byte |= 1 << (7 - bit);
            }
        }
    }

    let mut stored_checksum = 0u8;
    for bit in 0..8 {
        if bits[256 + bit] {
            stored_checksum |= 1 << (7 - bit);
        }
    }

    // Verify checksum
    let expected_checksum = Sha256::digest(entropy)[0];
    if stored_checksum != expected_checksum {
        entropy.zeroize();
        return Err(Bip39Error::ChecksumMismatch);
    }

    Ok(entropy)
}

/// Validate checksum of a mnemonic without returning entropy.
pub fn validate_checksum(words: &[String]) -> bool {
    decode(words).is_ok()
}

/// Generate a fresh 24-word mnemonic from random entropy.
pub fn generate() -> Result<(Vec<String>, [u8; 32]), Bip39Error> {
    use rand::TryRng;
    let mut entropy = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut entropy)
        .map_err(|_| Bip39Error::Entropy)?;
    let words = encode(&entropy)?;
    Ok((words, entropy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let entropy: [u8; 32] = [
            0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0x97, 0xE1, 0x4D, 0x45, 0xF1, 0x4E,
            0x1A, 0x1A, 0x6E, 0xAA, 0x52, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let words = encode(&entropy).unwrap();
        assert_eq!(words.len(), 24);
        let recovered = decode(&words).unwrap();
        assert_eq!(recovered, entropy);
    }

    #[test]
    fn encode_produces_24_words() {
        let entropy = [0xABu8; 32];
        let words = encode(&entropy).unwrap();
        assert_eq!(words.len(), 24);
        for word in &words {
            assert!(
                wordlist::WORDLIST.contains(&word.as_str()),
                "word '{}' not in wordlist",
                word
            );
        }
    }

    #[test]
    fn all_zeros_entropy() {
        let entropy = [0u8; 32];
        let words = encode(&entropy).unwrap();
        assert_eq!(words.len(), 24);
        // First word for all-zero bits should be "abandon" (index 0)
        assert_eq!(words[0], "abandon");
        let recovered = decode(&words).unwrap();
        assert_eq!(recovered, entropy);
    }

    #[test]
    fn all_ones_entropy() {
        let entropy = [0xFFu8; 32];
        let words = encode(&entropy).unwrap();
        assert_eq!(words.len(), 24);
        // All 1-bits → index 2047 = "zoo"
        assert_eq!(words[0], "zoo");
        let recovered = decode(&words).unwrap();
        assert_eq!(recovered, entropy);
    }

    #[test]
    fn checksum_detects_corruption() {
        let entropy = [0x42u8; 32];
        let mut words = encode(&entropy).unwrap();
        // Corrupt one word
        words[5] = "abandon".to_string();
        assert!(!validate_checksum(&words));
        assert!(matches!(decode(&words), Err(Bip39Error::ChecksumMismatch)));
    }

    #[test]
    fn wrong_word_count() {
        let words: Vec<String> = vec!["abandon".to_string(); 12];
        assert!(matches!(decode(&words), Err(Bip39Error::InvalidWordCount)));
    }

    #[test]
    fn unknown_word() {
        let mut words: Vec<String> = vec!["abandon".to_string(); 24];
        words[3] = "notaword".to_string();
        assert!(matches!(decode(&words), Err(Bip39Error::UnknownWord(_))));
    }

    #[test]
    fn generate_produces_valid_mnemonic() {
        let (words, entropy) = generate().unwrap();
        assert_eq!(words.len(), 24);
        assert!(validate_checksum(&words));
        let recovered = decode(&words).unwrap();
        assert_eq!(recovered, entropy);
    }

    #[test]
    fn two_generates_differ() {
        let (w1, _) = generate().unwrap();
        let (w2, _) = generate().unwrap();
        assert_ne!(w1, w2);
    }

    #[test]
    fn case_insensitive_decode() {
        let entropy = [0x42u8; 32];
        let words = encode(&entropy).unwrap();
        let upper: Vec<String> = words.iter().map(|w| w.to_uppercase()).collect();
        let recovered = decode(&upper).unwrap();
        assert_eq!(recovered, entropy);
    }

    #[test]
    fn wordlist_has_2048_entries() {
        assert_eq!(wordlist::WORDLIST.len(), 2048);
    }

    #[test]
    fn wordlist_sorted_and_unique() {
        let wl = wordlist::WORDLIST;
        for i in 1..wl.len() {
            assert!(
                wl[i] > wl[i - 1],
                "wordlist not sorted at index {}: '{}' <= '{}'",
                i,
                wl[i],
                wl[i - 1]
            );
        }
    }
}
