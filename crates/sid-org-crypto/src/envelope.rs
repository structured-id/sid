// SPDX-License-Identifier: AGPL-3.0-only
//! Envelope encryption helpers: AES-256-GCM wrap/unwrap.
//!
//! Layout (24 + ciphertext bytes for nonce+tag overhead):
//!   wrapped = nonce(12) || ciphertext_with_tag(...)

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::Rng;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::error::OrgCryptoError;

/// 12-byte nonce + AES-256-GCM ciphertext + 16-byte tag.
const NONCE_LEN: usize = 12;

/// Wrap plaintext with a 32-byte AES-256 key.
///
/// Returns `nonce(12) || ciphertext_with_tag` blob suitable for DB storage.
pub fn wrap(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, OrgCryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| OrgCryptoError::Aes(e.to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| OrgCryptoError::Aes(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwrap blob using a 32-byte AES-256 key.
///
/// Returns plaintext as `SecretBox<Vec<u8>>` so it zeroizes on drop.
pub fn unwrap(key: &[u8; 32], wrapped: &[u8]) -> Result<SecretBox<Vec<u8>>, OrgCryptoError> {
    if wrapped.len() < NONCE_LEN + 16 {
        return Err(OrgCryptoError::InvalidWrap(wrapped.len()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| OrgCryptoError::Aes(e.to_string()))?;
    // Length is checked above, so the conversion cannot fail.
    let nonce = Nonce::try_from(&wrapped[..NONCE_LEN])
        .map_err(|_| OrgCryptoError::InvalidWrap(wrapped.len()))?;
    let plaintext = cipher
        .decrypt(&nonce, &wrapped[NONCE_LEN..])
        .map_err(|e| OrgCryptoError::Aes(e.to_string()))?;
    Ok(SecretBox::new(Box::new(plaintext)))
}

/// Generate a fresh 32-byte symmetric key (DEK or KEK material).
pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rng().fill_bytes(&mut k);
    k
}

/// Wrap a key-material slice (32 bytes) — convenience for DEK wrapping.
pub fn wrap_key(kek: &[u8; 32], dek: &[u8; 32]) -> Result<Vec<u8>, OrgCryptoError> {
    wrap(kek, dek)
}

/// Unwrap a key-material blob into a `SecretBox` zeroizing on drop.
pub fn unwrap_key(kek: &[u8; 32], wrapped: &[u8]) -> Result<SecretBox<[u8; 32]>, OrgCryptoError> {
    let plain = unwrap(kek, wrapped)?;
    let bytes = plain.expose_secret();
    if bytes.len() != 32 {
        return Err(OrgCryptoError::InvalidKekLength(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    // `plain` zeroizes its Vec automatically on drop.
    let _ = plain;
    let secret = SecretBox::new(Box::new(arr));
    arr.zeroize();
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = random_key();
        let plaintext = b"super secret CA priv key bytes".to_vec();
        let wrapped = wrap(&kek, &plaintext).unwrap();
        assert_ne!(wrapped, plaintext);
        let unwrapped = unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped.expose_secret(), &plaintext);
    }

    #[test]
    fn wrap_unwrap_key_roundtrip() {
        let kek = random_key();
        let dek = random_key();
        let wrapped = wrap_key(&kek, &dek).unwrap();
        let unwrapped = unwrap_key(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped.expose_secret(), &dek);
    }

    #[test]
    fn wrap_with_wrong_kek_fails() {
        let kek1 = random_key();
        let kek2 = random_key();
        let wrapped = wrap(&kek1, b"data").unwrap();
        assert!(unwrap(&kek2, &wrapped).is_err());
    }

    #[test]
    fn invalid_wrap_blob_fails() {
        let kek = random_key();
        assert!(unwrap(&kek, b"too short").is_err());
        assert!(unwrap(&kek, &[0u8; 27]).is_err()); // <12+16
    }

    #[test]
    fn unwrap_key_rejects_wrong_length() {
        let kek = random_key();
        let wrapped = wrap(&kek, b"not 32 bytes").unwrap();
        assert!(matches!(
            unwrap_key(&kek, &wrapped).unwrap_err(),
            OrgCryptoError::InvalidKekLength(_)
        ));
    }
}
