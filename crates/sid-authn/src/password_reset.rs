// SPDX-License-Identifier: AGPL-3.0-only
//! Password reset links: a single-use 256-bit token, mailed to the mailbox
//! the account bound the requested address with.
//!
//! The link reaches its mailbox through durable work committed with the
//! reset session: the work names only the session, whose row keeps the token
//! sealed to it until the link is verified or expires, so a lost send is
//! retried with the same link and no copy of it is stored elsewhere.

use std::sync::Arc;

use rand::TryRng;
use sha2::{Digest, Sha256};
use sid_core::models::event::{Event, event_types};
use sid_core::models::{
    AuditEntry, MutationContext, NewWork, PASSWORD_RESET_EMAIL_KIND, PasswordResetSession,
    ProfileId, ResetSessionId, ResetSessionStatus, WorkKind, password_reset_sealing_context,
};
use sid_plugin::StorageBackend;

/// Attempts at emailing one link before its work fails: its retries fit in
/// the link's lifetime, past which the work expires unsent.
const EMAIL_ATTEMPTS: u32 = 8;

/// Why a reset could not be started or its link read.
#[derive(Debug, thiserror::Error)]
pub enum PasswordResetError {
    /// The stored token is not sealed to its session: it can never be sent.
    #[error("sealed token: {0}")]
    Sealed(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// A link still waiting for its email: the mailbox bound at the request,
/// the token, and until when the link works.
pub struct PendingReset {
    pub destination: String,
    pub token: secrecy::SecretString,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// The SHA-256 a reset session keeps of its link's token, hex-encoded.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Starts password resets and reads their pending links.
pub struct PasswordResetService {
    storage: Arc<dyn StorageBackend>,
    /// Seals each token to its session for the email delivery.
    keys: Arc<dyn sid_keys::KeyManager>,
}

impl PasswordResetService {
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn sid_keys::KeyManager>) -> Self {
        Self { storage, keys }
    }

    /// Start a reset of `profile` requested by the email key `email`, mailed
    /// to `destination`: the session, its audit entry, the event announcing
    /// it and the work emailing its link commit together.
    pub async fn request(
        &self,
        profile: ProfileId,
        email: &str,
        destination: &str,
    ) -> Result<ResetSessionId, PasswordResetError> {
        let mut token_bytes = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut token_bytes)
            .map_err(|_| {
                PasswordResetError::Internal("operating system random source unavailable".into())
            })?;
        let token = zeroize::Zeroizing::new(hex::encode(token_bytes));

        let mut session = PasswordResetSession::new(
            profile,
            email.to_string(),
            destination.to_string(),
            token_hash(&token),
        );
        session.sealed_token = crate::sealed_secret::seal(
            self.keys.as_ref(),
            &password_reset_sealing_context(session.id),
            token.as_bytes(),
        )
        .await
        .map_err(|e| PasswordResetError::Internal(format!("seal the token: {e}")))?;

        // The event names only the reset session: the event stream is read
        // beyond this service, so it never carries the token, a link or an
        // address.
        let requested = Event::new(
            format!("profile/{profile}"),
            event_types::PASSWORD_RESET_REQUESTED,
        )
        .with_data(serde_json::json!({
            "reset_session_id": session.id.to_string(),
        }));
        let mut mail = NewWork::new(
            WorkKind::new(PASSWORD_RESET_EMAIL_KIND).expect("the reset mail kind is valid"),
            session.id.0.as_bytes().to_vec(),
        );
        mail.expires_at = Some(session.expires_at);
        mail.max_attempts = EMAIL_ATTEMPTS;
        let ctx = MutationContext::from(AuditEntry::user(
            profile.to_string(),
            "password_reset.request",
            session.id.to_string(),
        ))
        .with_work(requested.relay())
        .with_work(mail);
        self.storage
            .create_reset_session(&session, ctx)
            .await
            .map_err(|e| PasswordResetError::Internal(e.to_string()))?;
        Ok(session.id)
    }

    /// What emailing reset `id`'s link needs while the link is still usable
    /// at `now`: none once it was verified or expired (or the session is
    /// gone), so a late retry sends nothing.
    pub async fn pending_delivery(
        &self,
        id: ResetSessionId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<PendingReset>, PasswordResetError> {
        let Some(session) = self
            .storage
            .get_reset_session(id)
            .await
            .map_err(|e| PasswordResetError::Internal(e.to_string()))?
        else {
            return Ok(None);
        };
        if session.status != ResetSessionStatus::Pending || now >= session.expires_at {
            return Ok(None);
        }
        let opened = crate::sealed_secret::open(
            self.keys.as_ref(),
            &password_reset_sealing_context(id),
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
                PasswordResetError::Sealed(e.to_string())
            }
            other => PasswordResetError::Internal(format!("open the token: {other}")),
        })?;
        let token = String::from_utf8(opened.secret.to_vec())
            .map_err(|_| PasswordResetError::Sealed("the sealed token is not text".into()))?;
        Ok(Some(PendingReset {
            destination: session.destination,
            token: secrecy::SecretString::from(token),
            expires_at: session.expires_at,
        }))
    }
}

#[cfg(test)]
mod tests;
