// SPDX-License-Identifier: AGPL-3.0-only
//! Mail of the authentication messages this server issues: sign-in links,
//! codes and password reset links. The delivery work names only its session
//! (and a code's issue);
//! the handler reads that session when it runs, so the token or code and the
//! mail exist only in the attempt. A link or code no longer usable
//! (consumed, expired, replaced) sends nothing; every retry of a usable one
//! sends the same secret to the address bound at the request.
//!
//! The email provider is read from the installation's stored settings at
//! every attempt, so all replicas send alike and a change applies to the
//! next attempt.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use secrecy::ExposeSecret;
use sid_authn::magic_link::{MagicLinkError, MagicLinkService};
use sid_authn::otp::{OTP_EMAIL_KIND, OtpError, OtpService};
use sid_authn::password_reset::{PasswordResetError, PasswordResetService};
use sid_authn::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use sid_core::models::event::{Event, event_types};
use sid_core::models::{
    ClaimedWork, MAGIC_LINK_EMAIL_KIND, NewWork, PASSWORD_RESET_EMAIL_KIND, ResetSessionId,
    WorkKind,
};
use sid_notify::TemplateEngine;
use sid_plugin::notification::{
    DeliveryError, NotificationChannel, NotificationPriority, Recipient,
};
use sid_plugin::storage::StorageBackend;

use crate::grpc::realm_service::{ProviderError, email_channel, stored_email_provider};

/// The template a sign-in link mail renders with.
const TEMPLATE: &str = "magic_link";

/// Delays between attempts of a link mail, inside the link's lifetime (the
/// work expires with the link).
const RETRIES: RetrySchedule = RetrySchedule::new(&[
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(5),
    std::time::Duration::from_secs(30),
    std::time::Duration::from_secs(120),
    std::time::Duration::from_secs(300),
]);

/// The channel a mail goes out on under the stored provider settings.
#[async_trait]
pub trait MailTransport: Send + Sync {
    async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String>;
}

/// The installation's configured email provider.
pub struct StoredProvider {
    storage: Arc<dyn StorageBackend>,
    keys: Arc<dyn sid_keys::KeyManager>,
}

impl StoredProvider {
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn sid_keys::KeyManager>) -> Self {
        Self { storage, keys }
    }
}

#[async_trait]
impl MailTransport for StoredProvider {
    async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String> {
        // No provider yet, or one an administrator must correct, leaves the
        // work waiting for it until the link expires.
        let cfg = stored_email_provider(self.storage.as_ref(), self.keys.as_ref())
            .await
            .map_err(|e: ProviderError| e.to_string())?
            .ok_or("no email provider is configured")?;
        email_channel(&cfg)
    }
}

/// Emails requested sign-in links.
pub struct MagicLinkMail {
    kind: WorkKind,
    links: Arc<MagicLinkService>,
    /// The account UI page the link opens.
    page: url::Url,
    transport: Arc<dyn MailTransport>,
    templates: TemplateEngine,
}

impl MagicLinkMail {
    pub fn new(
        links: Arc<MagicLinkService>,
        page: url::Url,
        transport: Arc<dyn MailTransport>,
    ) -> Self {
        Self {
            kind: WorkKind::new(MAGIC_LINK_EMAIL_KIND).expect("a valid work kind"),
            links,
            page,
            transport,
            templates: TemplateEngine::with_default_ce_templates(),
        }
    }
}

/// The link of session `id` with its `token`, on `page`.
pub(crate) fn link(page: &url::Url, id: uuid::Uuid, token: &str) -> url::Url {
    let mut link = page.clone();
    link.query_pairs_mut()
        .append_pair("session", &id.to_string())
        .append_pair("token", token);
    link
}

/// What a failed delivery means for the work: a refusal by the server or
/// the mailbox is final, an attempt whose result is unknown is ambiguous,
/// anything else is tried again.
pub(crate) fn outcome_of(error: DeliveryError) -> WorkOutcome {
    match error {
        DeliveryError::Ambiguous(e) => WorkOutcome::Ambiguous(e),
        e @ (DeliveryError::Rejected(_)
        | DeliveryError::InvalidRecipient(_)
        | DeliveryError::NotReachable) => WorkOutcome::Permanent(e.to_string()),
        e => WorkOutcome::Retry(e.to_string()),
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
        let data = serde_json::json!({
            "link": link.as_str(),
            "expires_minutes": minutes_left(pending.expires_at),
        });
        send(
            &self.templates,
            TEMPLATE,
            event_types::MAGIC_LINK_REQUESTED,
            data,
            self.transport.as_ref(),
            pending.destination,
        )
        .await
    }
}

/// Whole minutes until `expires_at`, at least one: what a mail tells about
/// the secret it carries.
fn minutes_left(expires_at: chrono::DateTime<Utc>) -> i64 {
    (expires_at - Utc::now()).num_minutes().max(1)
}

/// Render `template` with `data` and mail it to `destination`. Rendered here
/// and dropped with the attempt: no copy of the secret in `data` is stored
/// anywhere but its sealed session.
async fn send(
    templates: &TemplateEngine,
    template: &str,
    event_type: &str,
    data: serde_json::Value,
    transport: &dyn MailTransport,
    destination: String,
) -> WorkOutcome {
    let event = Event::new("sid-identity", event_type).with_data(data);
    let message = match templates.render(template, &event, NotificationPriority::Transactional) {
        Ok(message) => message,
        Err(e) => return WorkOutcome::Permanent(format!("render the {template} mail: {e}")),
    };
    let channel = match transport.channel().await {
        Ok(channel) => channel,
        Err(e) => return WorkOutcome::Retry(e),
    };
    let recipient = Recipient {
        profile_id: String::new(),
        email: Some(destination),
        phone: None,
        push_endpoint: None,
        device_token: None,
        locale: "en".into(),
    };
    match channel.deliver(&recipient, &message).await {
        Ok(receipt) => WorkOutcome::Done(Some(receipt.message_id)),
        Err(e) => outcome_of(e),
    }
}

/// How long an ended authentication mail keeps its record (its outcome, a
/// failure to review): the record holds only session and issue ids, and its
/// session is long gone by then.
const MAIL_RECORD_RETENTION: chrono::Duration = chrono::Duration::days(7);

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

/// The template a sign-in code mail renders with.
const CODE_TEMPLATE: &str = "otp";

/// Emails requested sign-in codes to the mailbox each was bound to.
pub struct CodeMail {
    kind: WorkKind,
    codes: Arc<OtpService>,
    transport: Arc<dyn MailTransport>,
    templates: TemplateEngine,
}

impl CodeMail {
    pub fn new(codes: Arc<OtpService>, transport: Arc<dyn MailTransport>) -> Self {
        Self {
            kind: WorkKind::new(OTP_EMAIL_KIND).expect("a valid work kind"),
            codes,
            transport,
            templates: TemplateEngine::with_default_ce_templates(),
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
        let data = serde_json::json!({
            "code": pending.code.expose_secret(),
            "expires_minutes": minutes_left(pending.expires_at),
            "purpose": "sign in",
        });
        send(
            &self.templates,
            CODE_TEMPLATE,
            event_types::OTP_REQUESTED,
            data,
            self.transport.as_ref(),
            pending.destination,
        )
        .await
    }
}

/// The template a password reset link mail renders with.
const RESET_TEMPLATE: &str = "password_reset";

/// Emails requested password reset links to the mailbox each was bound to.
pub struct ResetMail {
    kind: WorkKind,
    resets: Arc<PasswordResetService>,
    /// The account UI page the link opens.
    page: url::Url,
    transport: Arc<dyn MailTransport>,
    templates: TemplateEngine,
}

impl ResetMail {
    pub fn new(
        resets: Arc<PasswordResetService>,
        page: url::Url,
        transport: Arc<dyn MailTransport>,
    ) -> Self {
        Self {
            kind: WorkKind::new(PASSWORD_RESET_EMAIL_KIND).expect("a valid work kind"),
            resets,
            page,
            transport,
            templates: TemplateEngine::with_default_ce_templates(),
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
        let data = serde_json::json!({
            "link": link.as_str(),
            "expires_minutes": minutes_left(pending.expires_at),
        });
        send(
            &self.templates,
            RESET_TEMPLATE,
            event_types::PASSWORD_RESET_REQUESTED,
            data,
            self.transport.as_ref(),
            pending.destination,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
