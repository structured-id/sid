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
//!
//! A code for an account is owed its email as durable work naming the
//! session and the code's issue. The session binds the destination at the
//! request and keeps the code sealed to that issue, so a retry sends the
//! same code to the same mailbox, and a resent code supersedes the mail of
//! the one it replaced. The request is answered only once both are stored.

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use chrono::{DateTime, SubsecRound, Utc};
use rand::RngExt;
use sid_core::models::{NewWork, WorkKind};
use sid_plugin::CeremonyStateStore;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// The work that emails a requested code; its payload is the session id
/// followed by the issue id of the code it sends.
pub const OTP_EMAIL_KIND: &str = "auth.otp.email";

/// Attempts at emailing one code before its work fails: its retries fit in
/// the code's lifetime, past which the work expires unsent.
const EMAIL_ATTEMPTS: u32 = 8;

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
    /// The stored code is not sealed to its issue: it can never be sent.
    #[error("sealed code: {0}")]
    Sealed(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Where a requested code goes: the account's stored mailbox it was bound
/// to, or nowhere for an address that routes to no account (its session and
/// its unsent mail work exist only so that no answer tells the two apart).
#[derive(Debug, Clone, Copy)]
pub enum CodeDestination<'a> {
    Email(&'a str),
    None,
}

/// How requested codes are owed their email: the keys sealing each code to
/// its issue. The mail's work commits with the session in the ceremony state
/// store, which keeps both.
pub struct CodeDelivery {
    pub keys: Arc<dyn sid_keys::KeyManager>,
}

/// A code waiting for its email: the mailbox bound at the request, the code
/// and until when it works.
pub struct PendingCode {
    pub destination: String,
    pub code: secrecy::SecretString,
    pub expires_at: DateTime<Utc>,
}

/// An OTP session as the store holds it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredOtpSession {
    code_hash: String,
    target: String,
    expires_at: DateTime<Utc>,
    /// The current code's issue: a resent code gets a new one.
    issue: Uuid,
    /// The mailbox the code is sent to, bound at the request; `None` when
    /// it routes to no account.
    destination: Option<String>,
    /// The current code sealed to its issue, for its email.
    sealed_code: Vec<u8>,
    /// Used, expired or out of attempts: no code of it signs in, resends or
    /// is mailed. Ending is a compare-and-set from the exact state read, so
    /// a verification never ends a code other than the one it checked.
    ended: bool,
}

/// A stored session as read: its bytes (the expected value of a
/// compare-and-set) and its contents.
struct Read {
    bytes: Vec<u8>,
    session: StoredOtpSession,
}

/// The sealing context of the code of `session`'s issue `issue`.
fn sealing_context(session: Uuid, issue: Uuid) -> String {
    format!("otp:{session}:{issue}")
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
    delivery: CodeDelivery,
}

impl OtpService {
    /// Create an OTP service over the ceremony state every replica shares,
    /// owing each code's email through `delivery`.
    pub fn new(ceremonies: Arc<dyn CeremonyStateStore>, delivery: CodeDelivery) -> Self {
        Self {
            ceremonies,
            delivery,
        }
    }

    /// Request a new OTP code for `target` (the resolution key), emailed to
    /// `destination`.
    ///
    /// Returns the session ID and the plaintext code; the session keeps its
    /// hash for verification and the code sealed for the email.
    pub async fn request_otp(
        &self,
        target: &str,
        destination: CodeDestination<'_>,
    ) -> Result<(OtpRequestResult, String), OtpError> {
        self.admit_request(target).await?;
        let session_id = Uuid::now_v7();
        let destination = match destination {
            CodeDestination::Email(address) => Some(address.to_string()),
            CodeDestination::None => None,
        };
        let (session, code) = self.issue(session_id, target, destination).await?;
        let data = serde_json::to_vec(&session).map_err(|e| OtpError::Internal(e.to_string()))?;
        let email = Self::email(session_id, &session);
        // The session and its mail commit together: a code is never stored
        // without the work sending it, nor that work without its code.
        self.ceremonies
            .put_ceremony_state_owing(
                SESSIONS,
                &session_id.to_string(),
                &data,
                OTP_RETENTION,
                &email,
            )
            .await
            .map_err(store_error("store the session with its email"))?;
        Ok((Self::requested(session_id), code))
    }

    /// The live session under `key`: `None` when it is gone or ended.
    async fn live(&self, key: &str) -> Result<Option<Read>, OtpError> {
        let Some(bytes) = self
            .ceremonies
            .read_ceremony_state(SESSIONS, key)
            .await
            .map_err(store_error("read session"))?
        else {
            return Ok(None);
        };
        let session: StoredOtpSession =
            serde_json::from_slice(&bytes).map_err(|e| OtpError::Internal(e.to_string()))?;
        Ok((!session.ended).then_some(Read { bytes, session }))
    }

    /// End the session under `key` if it still holds exactly `read`:
    /// `false`, changing nothing, when it was replaced or ended meanwhile.
    /// Its code is gone either way only for the state this caller saw.
    async fn end(&self, key: &str, read: &Read) -> Result<bool, OtpError> {
        let mut ended = read.session.clone();
        ended.ended = true;
        ended.sealed_code.clear();
        let data = serde_json::to_vec(&ended).map_err(|e| OtpError::Internal(e.to_string()))?;
        self.ceremonies
            .replace_ceremony_state(SESSIONS, key, &read.bytes, &data, OTP_RETENTION)
            .await
            .map_err(store_error("end session"))
    }

    /// Send session `session_id` a new code in place of its current one, to
    /// the same mailbox: the session keeps its id and attempt count, and the
    /// mail of the code it replaces is superseded. `None` when the session
    /// is gone or changed meanwhile.
    pub async fn resend_otp(
        &self,
        session_id: &Uuid,
    ) -> Result<Option<(OtpRequestResult, String)>, OtpError> {
        let key = session_id.to_string();
        let Some(current) = self.live(&key).await? else {
            return Ok(None);
        };
        let previous = &current.session;
        self.admit_request(&previous.target).await?;
        let (session, code) = self
            .issue(*session_id, &previous.target, previous.destination.clone())
            .await?;
        let data = serde_json::to_vec(&session).map_err(|e| OtpError::Internal(e.to_string()))?;
        let email = Self::email(*session_id, &session);
        // The new code replaces the current one only with its mail owed: a
        // failed write leaves the current code and its mail in place.
        if !self
            .ceremonies
            .replace_ceremony_state_owing(
                SESSIONS,
                &key,
                &current.bytes,
                &data,
                OTP_RETENTION,
                &email,
            )
            .await
            .map_err(store_error("store the session with its email"))?
        {
            return Ok(None);
        }
        Ok(Some((Self::requested(*session_id), code)))
    }

    /// What emailing issue `issue` of session `session_id` needs while that
    /// code is still current and usable at `now`: none once it was used,
    /// expired or replaced, or when its session routes to no account.
    pub async fn pending_delivery(
        &self,
        session_id: Uuid,
        issue: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<PendingCode>, OtpError> {
        let Some(Read { session, .. }) = self.live(&session_id.to_string()).await? else {
            return Ok(None);
        };
        let Some(destination) = session.destination else {
            return Ok(None);
        };
        if session.issue != issue || now >= session.expires_at {
            return Ok(None);
        }
        let opened = crate::sealed_secret::open(
            self.delivery.keys.as_ref(),
            &sealing_context(session_id, issue),
            &session.sealed_code,
        )
        .await
        .map_err(|e| match e {
            crate::sealed_secret::SealedSecretError::KeyManager(
                sid_keys::KeyManagerError::ContextMismatch,
            )
            | crate::sealed_secret::SealedSecretError::NotSealed
            | crate::sealed_secret::SealedSecretError::Malformed(_)
            | crate::sealed_secret::SealedSecretError::ContextMismatch => {
                OtpError::Sealed(e.to_string())
            }
            other => OtpError::Internal(format!("open the code: {other}")),
        })?;
        let code = String::from_utf8(opened.secret.to_vec())
            .map_err(|_| OtpError::Sealed("the sealed code is not text".into()))?;
        Ok(Some(PendingCode {
            destination,
            code: secrecy::SecretString::from(code),
            expires_at: session.expires_at,
        }))
    }

    /// Count one request for `target`, refused past the limit.
    async fn admit_request(&self, target: &str) -> Result<(), OtpError> {
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
        Ok(())
    }

    /// A fresh code for session `session_id`, as its stored state and the
    /// plaintext.
    async fn issue(
        &self,
        session_id: Uuid,
        target: &str,
        destination: Option<String>,
    ) -> Result<(StoredOtpSession, String), OtpError> {
        let code = generate_otp_code();
        let code_hash =
            hash_code(&code).map_err(|e| OtpError::Internal(format!("hashing failed: {e}")))?;
        let issue = Uuid::now_v7();
        let sealed_code = crate::sealed_secret::seal(
            self.delivery.keys.as_ref(),
            &sealing_context(session_id, issue),
            code.as_bytes(),
        )
        .await
        .map_err(|e| OtpError::Internal(format!("seal the code: {e}")))?;
        let expiry = chrono::Duration::from_std(OTP_EXPIRY)
            .map_err(|e| OtpError::Internal(e.to_string()))?;
        Ok((
            StoredOtpSession {
                code_hash,
                target: target.to_string(),
                // At the precision every store keeps a deadline, so the
                // code and the work mailing it expire at the same instant.
                expires_at: (Utc::now() + expiry).trunc_subsecs(6),
                issue,
                destination,
                sealed_code,
                ended: false,
            },
            code,
        ))
    }

    /// The work emailing `session`'s current code. A session with no
    /// destination owes the same work, which sends nothing: storing it and
    /// its cost are alike for every address, so neither tells whether an
    /// account exists.
    fn email(session_id: Uuid, session: &StoredOtpSession) -> NewWork {
        let mut payload = session_id.as_bytes().to_vec();
        payload.extend_from_slice(session.issue.as_bytes());
        let mut email = NewWork::new(
            WorkKind::new(OTP_EMAIL_KIND).expect("the code email kind is valid"),
            payload,
        );
        email.expires_at = Some(session.expires_at);
        email.max_attempts = EMAIL_ATTEMPTS;
        email
    }

    fn requested(session_id: Uuid) -> OtpRequestResult {
        OtpRequestResult {
            session_id,
            code_length: OTP_CODE_LENGTH,
            expires_in_seconds: OTP_EXPIRY.as_secs() as u32,
            resend_available_in: 120,
        }
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
        let Some(read) = self.live(&key).await? else {
            return Ok(OtpVerifyResult::SessionNotFound);
        };

        // Ending a session ends only the state read here: a code resent in
        // the meantime stays usable.
        if Utc::now() >= read.session.expires_at {
            self.end(&key, &read).await?;
            return Ok(OtpVerifyResult::Expired);
        }

        let attempt = self
            .ceremonies
            .count_in_window(ATTEMPTS, &key, OTP_RETENTION)
            .await
            .map_err(store_error("count attempt"))?;
        if attempt > MAX_ATTEMPTS {
            self.end(&key, &read).await?;
            return Ok(OtpVerifyResult::MaxAttempts);
        }

        let remaining = MAX_ATTEMPTS - attempt;
        if !verify_code(code, &read.session.code_hash) {
            if remaining == 0 {
                self.end(&key, &read).await?;
                return Ok(OtpVerifyResult::MaxAttempts);
            }
            return Ok(OtpVerifyResult::InvalidCode {
                remaining_attempts: remaining as u32,
            });
        }

        // Signs in only by ending exactly the code checked: of concurrent
        // correct verifications one wins, and a code replaced by a resend
        // meanwhile is a wrong code, not a sign-in that spends the new one.
        if self.end(&key, &read).await? {
            return Ok(OtpVerifyResult::Success {
                target: read.session.target,
            });
        }
        match self.live(&key).await? {
            Some(_) if remaining > 0 => Ok(OtpVerifyResult::InvalidCode {
                remaining_attempts: remaining as u32,
            }),
            Some(_) => Ok(OtpVerifyResult::MaxAttempts),
            None => Ok(OtpVerifyResult::SessionNotFound),
        }
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
