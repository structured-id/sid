// SPDX-License-Identifier: Apache-2.0
//! The stored form of an encrypted value.
//!
//! A field carries the ciphertext, the nonce, the key version that produced it
//! and the context it was bound to. The context travels with the ciphertext
//! because it is the AAD: a field moved to another record decrypts to nothing.

use serde::{Deserialize, Serialize};

/// An encrypted field value with the metadata needed to decrypt it.
///
/// Context binding prevents ciphertext swapping between fields (for instance
/// moving one account's TOTP secret onto another's row).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedField {
    /// AES-256-GCM ciphertext.
    pub ciphertext: Vec<u8>,

    /// GCM nonce (96-bit / 12 bytes).
    pub nonce: [u8; 12],

    /// Which key version produced this ciphertext.
    /// Records with `key_version < current` need lazy rotation on read.
    pub key_version: u32,

    /// Bound context string (e.g., "totp:{profile_id}").
    /// Included as AAD in GCM encryption — prevents ciphertext swap attacks.
    pub context: String,
}

impl EncryptedField {
    /// Serialize to bytes for storage in a binary column.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Format: [key_version:4][nonce:12][context_len:4][context:N][ciphertext:M]
        let context_bytes = self.context.as_bytes();
        let mut buf = Vec::with_capacity(4 + 12 + 4 + context_bytes.len() + self.ciphertext.len());
        buf.extend_from_slice(&self.key_version.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(context_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(context_bytes);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from bytes (binary column).
    pub fn from_bytes(data: &[u8]) -> Result<Self, EncryptedFieldError> {
        if data.len() < 20 {
            return Err(EncryptedFieldError::InvalidFormat(
                "data too short (need at least 20 bytes)".into(),
            ));
        }

        let key_version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[4..16]);
        let context_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;

        if data.len() < 20 + context_len {
            return Err(EncryptedFieldError::InvalidFormat(
                "data too short for context".into(),
            ));
        }

        let context = String::from_utf8(data[20..20 + context_len].to_vec())
            .map_err(|e| EncryptedFieldError::InvalidFormat(e.to_string()))?;
        let ciphertext = data[20 + context_len..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            key_version,
            context,
        })
    }
}

/// Errors from encrypted field serialization.
#[derive(Debug, thiserror::Error)]
pub enum EncryptedFieldError {
    #[error("invalid format: {0}")]
    InvalidFormat(String),
}

#[cfg(test)]
mod tests;
