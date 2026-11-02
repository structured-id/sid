// SPDX-License-Identifier: AGPL-3.0-only
//! OTP Session Service: passwordless authentication entry point.
//!
//! Every piece of state lives in the authoritative ceremony state, so a code
//! requested on one replica is verified on any other against the same
//! attempt count:
//! - 8-digit codes (CSPRNG), stored only as an Argon2id hash
//! - 10 minute expiry
//! - 5 attempts per code, counted with an atomic increment
//! - a correct code is consumed with an atomic take, so it signs in once
//! - 3 requests per target per 15 minutes
//!
//! A store that cannot answer is an error, never a pass: limits that fail
//! open would let guessing run unbounded.

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use chrono::{DateTime, Utc};
use rand::RngExt;
use sid_plugin::CeremonyStateStore;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// OTP code length (8 digits per architecture spec).
const OTP_CODE_LENGTH: u32 = 8;
/// OTP expiry duration (10 minutes).
const OTP_EXPIRY: Duration = Duration::from_secs(600);
/// How long a session is kept: past its expiry, so an expired code is
/// reported as expired rather than unknown.
const OTP_RETENTION: Duration = Duration::from_secs(1200);
/// Maximum verification attempts per code.
const MAX_ATTEMPTS: u64 = 5;
/// Rate limit: max requests per target within the window.
const RATE_LIMIT_MAX: u64 = 3;
/// Rate limit window (15 minutes).
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(900);

/// Result of requesting a new OTP.
#[derive(Debug)]
pub struct OtpRequestResult {
    /// Session ID for verification/resend.
    pub session_id: Uuid,
    /// Code length hint for the UI.
    pub code_length: u32,
    /// Seconds until the code expires.
    pub expires_in_seconds: u32,
    /// Seconds until resend is allowed.
    pub resend_available_in: u32,
}

/// Result of verifying an OTP code.
#[derive(Debug)]
pub enum OtpVerifyResult {
    /// Code verified successfully.
    Success {
        /// The target that was verified.
        target: String,
    },
    /// Code was invalid.
    InvalidCode {
        /// Remaining attempts before lockout.
        remaining_attempts: u32,
    },
    /// Code has expired.
    Expired,
    /// Too many failed attempts: request a new code.
    MaxAttempts,
    /// Session not found (unknown, consumed, or past retention).
    SessionNotFound,
}

/// Error from OTP service.
#[derive(Debug, thiserror::Error)]
pub enum OtpError {
    #[error("rate limited: try again in {wait_seconds} seconds")]
    RateLimited { wait_seconds: u64 },
    #[error("internal error: {0}")]
    Internal(String),
}

/// An OTP session as the store holds it.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredOtpSession {
    code_hash: String,
    target: String,
    expires_at: DateTime<Utc>,
}

/// Namespaces of the sessions, their attempt counts and the per-target
/// request counts. A session's id is never reused, so its count needs no
/// clearing: it expires with the session's retention.
const SESSIONS: &str = "otp-session";
const ATTEMPTS: &str = "otp-attempts";
const REQUESTS: &str = "otp-requests";

fn store_error(what: &str) -> impl Fn(sid_core::Error) -> OtpError + '_ {
    move |e| OtpError::Internal(format!("{what}: {e}"))
}

/// OTP session service over the ceremony state every replica shares.
pub struct OtpService {
    ceremonies: Arc<dyn CeremonyStateStore>,
}

impl OtpService {
    /// Create an OTP service over the ceremony state every replica shares.
    pub fn new(ceremonies: Arc<dyn CeremonyStateStore>) -> Self {
        Self { ceremonies }
    }

    /// Request a new OTP code for a target.
    ///
    /// Returns the session ID and the plaintext code (for delivery via
    /// transport); only its hash is stored.
    pub async fn request_otp(&self, target: &str) -> Result<(OtpRequestResult, String), OtpError> {
        let requests = self
            .ceremonies
            .count_in_window(REQUESTS, target, RATE_LIMIT_WINDOW)
            .await
            .map_err(store_error("rate limit"))?;
        if requests > RATE_LIMIT_MAX {
            return Err(OtpError::RateLimited {
                wait_seconds: RATE_LIMIT_WINDOW.as_secs(),
            });
        }

        let code = generate_otp_code();
        let code_hash =
            hash_code(&code).map_err(|e| OtpError::Internal(format!("hashing failed: {e}")))?;
        let session_id = Uuid::now_v7();
        let expiry = chrono::Duration::from_std(OTP_EXPIRY)
            .map_err(|e| OtpError::Internal(e.to_string()))?;
        let session = StoredOtpSession {
            code_hash,
            target: target.to_string(),
            expires_at: Utc::now() + expiry,
        };
        let data = serde_json::to_vec(&session).map_err(|e| OtpError::Internal(e.to_string()))?;
        self.ceremonies
            .put_ceremony_state(SESSIONS, &session_id.to_string(), &data, OTP_RETENTION)
            .await
            .map_err(store_error("store session"))?;

        Ok((
            OtpRequestResult {
                session_id,
                code_length: OTP_CODE_LENGTH,
                expires_in_seconds: OTP_EXPIRY.as_secs() as u32,
                resend_available_in: 120,
            },
            code,
        ))
    }

    /// Verify an OTP code against a session. Each call counts one attempt
    /// before the code is checked; the session ends at the limit, at expiry,
    /// and on the one successful verification.
    pub async fn verify_otp(
        &self,
        session_id: &Uuid,
        code: &str,
    ) -> Result<OtpVerifyResult, OtpError> {
        let key = session_id.to_string();
        let Some(data) = self
            .ceremonies
            .read_ceremony_state(SESSIONS, &key)
            .await
            .map_err(store_error("read session"))?
        else {
            return Ok(OtpVerifyResult::SessionNotFound);
        };
        let session: StoredOtpSession =
            serde_json::from_slice(&data).map_err(|e| OtpError::Internal(e.to_string()))?;

        if Utc::now() >= session.expires_at {
            self.end(&key).await?;
            return Ok(OtpVerifyResult::Expired);
        }

        let attempt = self
            .ceremonies
            .count_in_window(ATTEMPTS, &key, OTP_RETENTION)
            .await
            .map_err(store_error("count attempt"))?;
        if attempt > MAX_ATTEMPTS {
            self.end(&key).await?;
            return Ok(OtpVerifyResult::MaxAttempts);
        }

        if !verify_code(code, &session.code_hash) {
            let remaining = MAX_ATTEMPTS - attempt;
            if remaining == 0 {
                self.end(&key).await?;
                return Ok(OtpVerifyResult::MaxAttempts);
            }
            return Ok(OtpVerifyResult::InvalidCode {
                remaining_attempts: remaining as u32,
            });
        }

        // Of concurrent correct verifications, only the one that takes the
        // session signs in.
        match self
            .ceremonies
            .take_ceremony_state(SESSIONS, &key)
            .await
            .map_err(store_error("consume session"))?
        {
            Some(_) => Ok(OtpVerifyResult::Success {
                target: session.target,
            }),
            None => Ok(OtpVerifyResult::SessionNotFound),
        }
    }

    /// Get the target for a session (for resend).
    pub async fn get_session_target(&self, session_id: &Uuid) -> Result<Option<String>, OtpError> {
        let Some(data) = self
            .ceremonies
            .read_ceremony_state(SESSIONS, &session_id.to_string())
            .await
            .map_err(store_error("read session"))?
        else {
            return Ok(None);
        };
        let session: StoredOtpSession =
            serde_json::from_slice(&data).map_err(|e| OtpError::Internal(e.to_string()))?;
        Ok(Some(session.target))
    }

    /// End a session: its code is gone, and no verification takes it.
    async fn end(&self, key: &str) -> Result<(), OtpError> {
        self.ceremonies
            .take_ceremony_state(SESSIONS, key)
            .await
            .map(|_| ())
            .map_err(store_error("end session"))
    }
}

/// Generate an 8-digit OTP code using CSPRNG.
fn generate_otp_code() -> String {
    let mut rng = rand::rng();
    let code: u32 = rng.random_range(0..10u32.pow(OTP_CODE_LENGTH));
    format!("{:0>width$}", code, width = OTP_CODE_LENGTH as usize)
}

/// Hash an OTP code with argon2id.
fn hash_code(code: &str) -> Result<String, String> {
    PasswordHasher::<PasswordHash>::hash_password(&Argon2::default(), code.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Verify an OTP code against an argon2 hash.
fn verify_code(code: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(code.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests;
