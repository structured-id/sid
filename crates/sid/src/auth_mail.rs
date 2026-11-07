// SPDX-License-Identifier: AGPL-3.0-only
//! Mail of the authentication messages an installation issues: sign-in
//! links, codes and password reset links. The delivery work names only its
//! session (and a code's issue); the handler reads that session when it
//! runs, so the token or code and the mail exist only in the attempt. A link
//! or code no longer usable (consumed, expired, replaced) sends nothing;
//! every retry of a usable one sends the same secret to the address bound at
//! the request.
//!
//! Rendering and sending are the host's ([`AuthMailDelivery`]): its
//! templates and its email provider. What is owed, to whom, until when, and
//! what a delivery's outcome means for the work are decided here.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use sid_authn::magic_link::{MagicLinkError, MagicLinkService};
use sid_authn::otp::{OTP_EMAIL_KIND, OtpError, OtpService};
use sid_authn::password_reset::{PasswordResetError, PasswordResetService};
use sid_authn::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use sid_core::models::{
    ClaimedWork, MAGIC_LINK_EMAIL_KIND, NewWork, PASSWORD_RESET_EMAIL_KIND, ResetSessionId,
    WorkKind,
};
use sid_plugin::notification::DeliveryError;

/// Delays between attempts of an authentication mail, inside its secret's
/// lifetime (the work expires with it).
const RETRIES: RetrySchedule = RetrySchedule::new(&[
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(5),
    std::time::Duration::from_secs(30),
    std::time::Duration::from_secs(120),
    std::time::Duration::from_secs(300),
]);

/// Which authentication message a mail carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMessage {
    /// A sign-in link; the secret is the link.
    MagicLink,
    /// A sign-in code; the secret is the code.
    SignInCode,
    /// A password reset link; the secret is the link.
    PasswordReset,
}

/// One owed authentication mail, as an attempt sends it.
pub struct OwedMail {
    pub message: AuthMessage,
    /// The mailbox bound at the request.
    pub destination: String,
    /// The link or code; it exists only for this attempt.
    pub secret: SecretString,
    /// Whole minutes the secret stays usable, at least one.
    pub expires_minutes: i64,
}

/// Why a mail did not go out.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// No usable email provider now: the mail waits for one.
    #[error("{0}")]
    Unavailable(String),
    /// The message could not be rendered: no attempt can send it.
    #[error("render the mail: {0}")]
    Render(String),
    /// The provider's answer.
    #[error(transparent)]
    Delivery(#[from] DeliveryError),
}

/// The host's rendering and sending of an authentication mail.
#[async_trait]
pub trait AuthMailDelivery: Send + Sync {
    /// Render `mail` and send it; the provider's message id.
    async fn deliver(&self, mail: &OwedMail) -> Result<String, MailError>;
}

/// The link of session `id` with its `token`, on `page`.
pub fn link(page: &url::Url, id: uuid::Uuid, token: &str) -> url::Url {
    let mut link = page.clone();
    link.query_pairs_mut()
        .append_pair("session", &id.to_string())
        .append_pair("token", token);
    link
}

/// What a failed delivery means for the work: a refusal by the server or
/// the mailbox is final, an attempt whose result is unknown is ambiguous,
/// anything else is tried again.
pub fn outcome_of(error: DeliveryError) -> WorkOutcome {
    match error {
        DeliveryError::Ambiguous(e) => WorkOutcome::Ambiguous(e),
        e @ (DeliveryError::Rejected(_)
        | DeliveryError::InvalidRecipient(_)
        | DeliveryError::NotReachable) => WorkOutcome::Permanent(e.to_string()),
        e => WorkOutcome::Retry(e.to_string()),
    }
}

/// Whole minutes until `expires_at`, at least one: what a mail tells about
/// the secret it carries.
fn minutes_left(expires_at: chrono::DateTime<Utc>) -> i64 {
    (expires_at - Utc::now()).num_minutes().max(1)
}

/// Hand `mail` to the host and settle the work by its answer.
async fn send(delivery: &dyn AuthMailDelivery, mail: OwedMail) -> WorkOutcome {
    match delivery.deliver(&mail).await {
        Ok(message_id) => WorkOutcome::Done(Some(message_id)),
        Err(MailError::Unavailable(e)) => WorkOutcome::Retry(e),
        Err(e @ MailError::Render(_)) => WorkOutcome::Permanent(e.to_string()),
        Err(MailError::Delivery(e)) => outcome_of(e),
    }
}

/// How long an ended authentication mail keeps its record (its outcome, a
/// failure to review): the record holds only session and issue ids, and its
/// session is long gone by then.
pub const MAIL_RECORD_RETENTION: chrono::Duration = chrono::Duration::days(7);

/// Drop the authentication mails that ended (sent, failed, expired) more than
/// [`MAIL_RECORD_RETENTION`] before `now`; open ones are untouched. Returns
/// how many records were dropped. Idempotent, so replicas may run it at once.
pub async fn purge_ended_mail(
    store: &dyn sid_plugin::WorkStore,
    now: chrono::DateTime<Utc>,
) -> sid_core::Result<u64> {
    let before = now - MAIL_RECORD_RETENTION;
    let mut dropped = 0;
    for kind in [
        MAGIC_LINK_EMAIL_KIND,
        OTP_EMAIL_KIND,
        PASSWORD_RESET_EMAIL_KIND,
    ] {
        let kind = WorkKind::new(kind).expect("the mail kinds are valid");
        dropped += store.purge_ended_work(&kind, before).await?;
    }
    Ok(dropped)
}

/// Emails requested sign-in links.
pub struct MagicLinkMail {
    kind: WorkKind,
    links: Arc<MagicLinkService>,
    /// The account UI page the link opens.
    page: url::Url,
    delivery: Arc<dyn AuthMailDelivery>,
}

impl MagicLinkMail {
    pub fn new(
        links: Arc<MagicLinkService>,
        page: url::Url,
        delivery: Arc<dyn AuthMailDelivery>,
    ) -> Self {
        Self {
            kind: WorkKind::new(MAGIC_LINK_EMAIL_KIND).expect("a valid work kind"),
            links,
            page,
            delivery,
        }
    }
}

#[async_trait]
impl WorkHandler for MagicLinkMail {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RETRIES
    }

    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let Ok(id) = uuid::Uuid::from_slice(&work.payload) else {
            return WorkOutcome::Permanent("the work does not name a link session".into());
        };
        let pending = match self.links.pending_delivery(id, Utc::now()).await {
            Ok(Some(pending)) => pending,
            Ok(None) => return WorkOutcome::Done(Some("the link is no longer usable".into())),
            Err(e @ MagicLinkError::Sealed(_)) => return WorkOutcome::Permanent(e.to_string()),
            Err(e) => return WorkOutcome::Retry(format!("read the link: {e}")),
        };
        let link = link(&self.page, id, pending.token.expose_secret());
        send(
            self.delivery.as_ref(),
            OwedMail {
                message: AuthMessage::MagicLink,
                destination: pending.destination,
                secret: SecretString::from(link.to_string()),
                expires_minutes: minutes_left(pending.expires_at),
            },
        )
        .await
    }
}

/// Emails requested sign-in codes to the mailbox each was bound to.
pub struct CodeMail {
    kind: WorkKind,
    codes: Arc<OtpService>,
    delivery: Arc<dyn AuthMailDelivery>,
}

impl CodeMail {
    pub fn new(codes: Arc<OtpService>, delivery: Arc<dyn AuthMailDelivery>) -> Self {
        Self {
            kind: WorkKind::new(OTP_EMAIL_KIND).expect("a valid work kind"),
            codes,
            delivery,
        }
    }
}

#[async_trait]
impl WorkHandler for CodeMail {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RETRIES
    }

    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let (Some(session), Some(issue)) = (
            work.payload
                .get(..16)
                .and_then(|b| uuid::Uuid::from_slice(b).ok()),
            work.payload
                .get(16..)
                .and_then(|b| uuid::Uuid::from_slice(b).ok()),
        ) else {
            return WorkOutcome::Permanent("the work does not name a code".into());
        };
        let pending = match self
            .codes
            .pending_delivery(session, issue, Utc::now())
            .await
        {
            Ok(Some(pending)) => pending,
            Ok(None) => return WorkOutcome::Done(Some("the code is no longer current".into())),
            Err(e @ OtpError::Sealed(_)) => return WorkOutcome::Permanent(e.to_string()),
            Err(e) => return WorkOutcome::Retry(format!("read the code: {e}")),
        };
        send(
            self.delivery.as_ref(),
            OwedMail {
                message: AuthMessage::SignInCode,
                destination: pending.destination,
                secret: pending.code,
                expires_minutes: minutes_left(pending.expires_at),
            },
        )
        .await
    }
}

/// Emails requested password reset links to the mailbox each was bound to.
pub struct ResetMail {
    kind: WorkKind,
    resets: Arc<PasswordResetService>,
    /// The account UI page the link opens.
    page: url::Url,
    delivery: Arc<dyn AuthMailDelivery>,
}

impl ResetMail {
    pub fn new(
        resets: Arc<PasswordResetService>,
        page: url::Url,
        delivery: Arc<dyn AuthMailDelivery>,
    ) -> Self {
        Self {
            kind: WorkKind::new(PASSWORD_RESET_EMAIL_KIND).expect("a valid work kind"),
            resets,
            page,
            delivery,
        }
    }
}

#[async_trait]
impl WorkHandler for ResetMail {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RETRIES
    }

    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let Ok(id) = uuid::Uuid::from_slice(&work.payload) else {
            return WorkOutcome::Permanent("the work does not name a reset session".into());
        };
        let pending = match self
            .resets
            .pending_delivery(ResetSessionId(id), Utc::now())
            .await
        {
            Ok(Some(pending)) => pending,
            Ok(None) => return WorkOutcome::Done(Some("the link is no longer usable".into())),
            Err(e @ PasswordResetError::Sealed(_)) => return WorkOutcome::Permanent(e.to_string()),
            Err(e) => return WorkOutcome::Retry(format!("read the reset: {e}")),
        };
        let link = link(&self.page, id, pending.token.expose_secret());
        send(
            self.delivery.as_ref(),
            OwedMail {
                message: AuthMessage::PasswordReset,
                destination: pending.destination,
                secret: SecretString::from(link.to_string()),
                expires_minutes: minutes_left(pending.expires_at),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests;
