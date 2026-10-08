// SPDX-License-Identifier: AGPL-3.0-only
//! Magic Link passwordless authentication.
//!
//! 256-bit CSPRNG token delivered via email link. Single-use, 15-minute TTL.
//! Corporate profiles only (CE: site admin opt-in).
//!
//! Properties:
//! - 256-bit URL-safe base64 token
//! - Argon2id hashed storage
//! - 15 minute expiry
//! - Single-use (consumed on first verification)
//! - 3 requests per email per 15 minutes (rate limiting)

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sid_core::models::{MAGIC_LINK_RATE_LIMIT_MAX, MagicLinkSession};
use sid_plugin::StorageBackend;
use std::sync::Arc;

/// Token size in bytes (256-bit).
const MAGIC_LINK_TOKEN_BYTES: usize = 32;

/// Result of requesting a new magic link.
#[derive(Debug)]
pub struct MagicLinkRequestResult {
    /// Session ID for verification reference.
    pub session_id: uuid::Uuid,
    /// Seconds until the token expires.
    pub expires_in_seconds: u32,
}

/// Result of verifying a magic link token.
#[derive(Debug)]
pub enum MagicLinkVerifyResult {
    /// Token verified successfully.
    Success {
        /// The email that was verified.
        email: String,
    },
    /// Token was invalid.
    InvalidToken,
    /// Token has expired.
    Expired,
    /// Token was already consumed (single-use).
    AlreadyConsumed,
    /// Session not found.
    SessionNotFound,
}

/// Error from magic link service.
#[derive(Debug, thiserror::Error)]
pub enum MagicLinkError {
    #[error("rate limited: try again in {wait_seconds} seconds")]
    RateLimited { wait_seconds: u64 },
    #[error("internal error: {0}")]
    Internal(String),
}

/// Magic link session service.
///
/// Manages magic link lifecycle: token generation, hashing, verification,
/// rate limiting, and single-use enforcement.
/// Uses StorageBackend for persistence (survives restarts).
pub struct MagicLinkService {
    storage: Arc<dyn StorageBackend>,
}

impl MagicLinkService {
    /// Create a new magic link service backed by storage.
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// Request a new magic link token for an email.
    ///
    /// Returns the session metadata and the plaintext token (for building the URL).
    /// The token is Argon2-hashed before storage — only the caller has the plaintext.
    pub async fn request_magic_link(
        &self,
        email: &str,
    ) -> Result<(MagicLinkRequestResult, String), MagicLinkError> {
        // Check rate limit via storage
        let active_count = self
            .storage
            .count_active_magic_links_for_email(email)
            .await
            .map_err(|e| MagicLinkError::Internal(e.to_string()))?;

        if active_count >= MAGIC_LINK_RATE_LIMIT_MAX {
            return Err(MagicLinkError::RateLimited {
                wait_seconds: 900, // worst case: full window
            });
        }

        // Generate 256-bit token
        let token = generate_token();

        // Hash with Argon2
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let token_hash = argon2
            .hash_password(token.as_bytes(), &salt)
            .map_err(|e| MagicLinkError::Internal(format!("hash failed: {}", e)))?
            .to_string();

        let session = MagicLinkSession::new(email, token_hash);
        let session_id = session.id;
        let expires_in = sid_core::models::MAGIC_LINK_EXPIRY_SECS as u32;

        // Persist to storage
        let audit: sid_core::models::MutationContext =
            sid_core::models::AuditEntry::system("magic_link.create", session_id.to_string())
                .into();
        self.storage
            .create_magic_link_session(&session, audit)
            .await
            .map_err(|e| MagicLinkError::Internal(e.to_string()))?;

        let result = MagicLinkRequestResult {
            session_id,
            expires_in_seconds: expires_in,
        };

        Ok((result, token))
    }

    /// Verify a magic link token. Single-use: consumed on first successful verify.
    ///
    /// Uses atomic try_consume to prevent TOCTOU race: two instances verifying
    /// the same token simultaneously — only one succeeds (the one that atomically
    /// sets consumed = false → true first). A storage failure is an error, never
    /// an answer about the link.
    pub async fn verify_magic_link(
        &self,
        session_id: uuid::Uuid,
        token: &str,
    ) -> Result<MagicLinkVerifyResult, MagicLinkError> {
        // First, get the session to verify the token hash (non-destructive read).
        // We need the hash before consuming — can't verify after consumption
        // because try_consume returns the consumed session.
        let Some(session) = self
            .storage
            .get_magic_link_session(session_id)
            .await
            .map_err(|e| MagicLinkError::Internal(e.to_string()))?
        else {
            return Ok(MagicLinkVerifyResult::SessionNotFound);
        };

        // Check expiry
        if session.is_expired() {
            return Ok(MagicLinkVerifyResult::Expired);
        }

        // Check single-use (fast path — atomic check below is the real guard)
        if session.consumed {
            return Ok(MagicLinkVerifyResult::AlreadyConsumed);
        }

        // Verify token against Argon2 hash
        let parsed_hash = match PasswordHash::new(&session.token_hash) {
            Ok(h) => h,
            Err(_) => return Ok(MagicLinkVerifyResult::InvalidToken),
        };

        if Argon2::default()
            .verify_password(token.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Ok(MagicLinkVerifyResult::InvalidToken);
        }

        // Atomically consume — prevents TOCTOU race between check and consume.
        // Only one instance wins; others get None (already consumed).
        let audit: sid_core::models::MutationContext =
            sid_core::models::AuditEntry::system("magic_link.consume", session_id.to_string())
                .into();
        let consumed = self
            .storage
            .try_consume_magic_link_session(session_id, audit)
            .await
            .map_err(|e| MagicLinkError::Internal(e.to_string()))?;
        Ok(match consumed {
            Some(consumed_session) => MagicLinkVerifyResult::Success {
                email: consumed_session.email,
            },
            // Another instance consumed it between our read and this atomic consume
            None => MagicLinkVerifyResult::AlreadyConsumed,
        })
    }

    /// Remove all expired sessions (background cleanup).
    pub async fn cleanup(&self) -> Result<u64, MagicLinkError> {
        let audit: sid_core::models::MutationContext =
            sid_core::models::AuditEntry::system("magic_link.cleanup", "expired_sessions").into();
        self.storage
            .delete_expired_magic_link_sessions(audit)
            .await
            .map_err(|e| MagicLinkError::Internal(e.to_string()))
    }
}

/// Generate a 256-bit URL-safe base64 token.
fn generate_token() -> String {
    let mut bytes = [0u8; MAGIC_LINK_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests;
