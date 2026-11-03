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
//!
//! The link reaches its address through durable work committed with the
//! session: the work names only the session, whose row keeps the token
//! sealed to it until the link is consumed or expires, so a lost send is
//! retried with the same link and no copy of it is stored elsewhere.

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRng;
use sid_core::models::{
    MAGIC_LINK_EMAIL_KIND, MAGIC_LINK_RATE_LIMIT_MAX, MagicLinkSession, NewWork, WorkKind,
    magic_link_sealing_context,
};
use sid_plugin::StorageBackend;
use std::sync::Arc;

/// Attempts at emailing one link before its work fails: its retries fit in
/// the link's lifetime, past which the work expires unsent.
const EMAIL_ATTEMPTS: u32 = 8;

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
    /// The queue of link emails is at its capacity: no session was created.
    #[error("delivery backlog: {0}")]
    DeliveryBacklog(String),
    /// The stored token is not sealed to its session: it can never be sent.
    #[error("sealed token: {0}")]
    Sealed(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// A link still waiting for its email: the mailbox bound at the request,
/// the token, and until when the link works.
pub struct PendingLink {
    pub session_id: uuid::Uuid,
    pub destination: String,
    pub token: secrecy::SecretString,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Magic link session service.
///
/// Manages magic link lifecycle: token generation, hashing, verification,
/// rate limiting, and single-use enforcement.
/// Uses StorageBackend for persistence (survives restarts).
pub struct MagicLinkService {
    storage: Arc<dyn StorageBackend>,
    /// Seals each token to its session for the email delivery.
    keys: Arc<dyn sid_keys::KeyManager>,
}

impl MagicLinkService {
    /// Create a new magic link service backed by storage, sealing tokens
    /// under `keys`.
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn sid_keys::KeyManager>) -> Self {
        Self { storage, keys }
    }

    /// Request a new magic link token for an email: the session and the work
    /// emailing its link commit together.
    ///
    /// Returns the session metadata and the plaintext token. The stored
    /// session keeps its Argon2 hash for verification and the token sealed
    /// to it for the delivery.
    pub async fn request_magic_link(
        &self,
        email: &str,
        destination: &str,
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
        let token_hash =
            PasswordHasher::<PasswordHash>::hash_password(&Argon2::default(), token.as_bytes())
                .map_err(|e| MagicLinkError::Internal(format!("hash failed: {}", e)))?
                .to_string();

        let mut session = MagicLinkSession::new(email, destination, token_hash);
        let session_id = session.id;
        let expires_in = sid_core::models::MAGIC_LINK_EXPIRY_SECS as u32;
        session.sealed_token = crate::sealed_secret::seal(
            self.keys.as_ref(),
            &magic_link_sealing_context(session_id),
            token.as_bytes(),
        )
        .await
        .map_err(|e| MagicLinkError::Internal(format!("seal the token: {e}")))?;

        let mut email = NewWork::new(
            WorkKind::new(MAGIC_LINK_EMAIL_KIND).expect("the magic link kind is valid"),
            session_id.as_bytes().to_vec(),
        );
        email.expires_at = Some(session.expires_at);
        email.max_attempts = EMAIL_ATTEMPTS;
        let audit = sid_core::models::MutationContext::from(sid_core::models::AuditEntry::system(
            "magic_link.create",
            session_id.to_string(),
        ))
        .with_work(email);
        self.storage
            .create_magic_link_session(&session, audit)
            .await
            .map_err(|e| match e {
                sid_core::Error::ResourceExhausted(why) => MagicLinkError::DeliveryBacklog(why),
                other => MagicLinkError::Internal(other.to_string()),
            })?;

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

    /// What emailing session `id`'s link needs while the link is still
    /// usable at `now`: none once it was consumed or expired (or the session
    /// is gone), so a late retry sends nothing.
    pub async fn pending_delivery(
        &self,
        id: uuid::Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<PendingLink>, MagicLinkError> {
        let Some(session) = self
            .storage
            .get_magic_link_session(id)
            .await
            .map_err(|e| MagicLinkError::Internal(e.to_string()))?
        else {
            return Ok(None);
        };
        if session.consumed || now >= session.expires_at {
            return Ok(None);
        }
        let opened = crate::sealed_secret::open(
            self.keys.as_ref(),
            &magic_link_sealing_context(id),
            &session.sealed_token,
        )
        .await
        .map_err(|e| match e {
            crate::sealed_secret::SealedSecretError::KeyManager(
                sid_keys::KeyManagerError::ContextMismatch,
            )
            | crate::sealed_secret::SealedSecretError::NotSealed
            | crate::sealed_secret::SealedSecretError::Malformed(_)
            | crate::sealed_secret::SealedSecretError::ContextMismatch => {
                MagicLinkError::Sealed(e.to_string())
            }
            other => MagicLinkError::Internal(format!("open the token: {other}")),
        })?;
        let token = String::from_utf8(opened.secret.to_vec())
            .map_err(|_| MagicLinkError::Sealed("the sealed token is not text".into()))?;
        Ok(Some(PendingLink {
            session_id: id,
            destination: session.destination,
            token: secrecy::SecretString::from(token),
            expires_at: session.expires_at,
        }))
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
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the operating system random source is available");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests;
