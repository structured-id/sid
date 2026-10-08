// SPDX-License-Identifier: Apache-2.0
//! Field-level encryption for applications that store secrets of their own.
//!
//! An application encrypts a stored value with a key derived from a master
//! secret it supplies, and stores the ciphertext together with the non-secret
//! parameters needed to derive that key again. A database dump without the
//! master secret yields nothing usable.
//!
//! The crate depends on no identity, storage or server crate: an embedding
//! application can encrypt its own credentials without linking any of them.
//!
//! ```
//! use std::sync::Arc;
//! use secrecy::SecretBox;
//! use sid_keys::{KeyManager, KeyVersionParams, RustCryptoPrimitives, SoftwareKeyManager};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let master = SecretBox::new(Box::new([7u8; 32]));
//! let versions = vec![KeyVersionParams::new(1, vec![1, 2, 3, 4], "key-v1")];
//! let manager = SoftwareKeyManager::new(master, versions, Arc::new(RustCryptoPrimitives::new()))?;
//!
//! let field = manager.encrypt(b"secret value", "totp:alice").await?;
//! assert_eq!(manager.decrypt(&field).await?, b"secret value");
//! # Ok(())
//! # }
//! ```

pub mod crypto;
pub mod field;
pub mod manager;

pub use crypto::{CryptoError, CryptoPrimitives, RustCryptoPrimitives};
pub use field::{EncryptedField, EncryptedFieldError};
pub use manager::{
    KeyDerivation, KeyManager, KeyManagerError, KeyManagerResult, KeyVersionParams,
    SoftwareKeyManager,
};
