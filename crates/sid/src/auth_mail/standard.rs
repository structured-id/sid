// SPDX-License-Identifier: AGPL-3.0-only
//! SID's standard authentication mail: the engine renders each message with
//! its standard text and sends it over the host's notification channel, so a
//! service and an embedding application send the same mail.

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use sid_core::models::event::event_types;
use sid_plugin::notification::{
    NotificationChannel, NotificationPriority, Recipient, RenderedMessage,
};

use super::{AuthMailDelivery, AuthMessage, MailError, OwedMail};

/// The channel a mail goes out on, asked at every attempt: a provider the
/// host changes applies to the next attempt.
#[async_trait]
pub trait MailTransport: Send + Sync {
    /// The channel to send on now; why there is none, when the mail must
    /// wait for one.
    async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String>;
}

/// A host's one notification channel, used for every attempt.
pub struct HostChannel(pub Arc<dyn NotificationChannel>);

#[async_trait]
impl MailTransport for HostChannel {
    async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String> {
        Ok(Arc::clone(&self.0))
    }
}

/// Authentication mail rendered with the standard text and sent over
/// `transport`. Rendered per attempt and dropped with it: no copy of the
/// secret is kept anywhere but its sealed session.
pub struct StandardMail {
    transport: Arc<dyn MailTransport>,
}

impl StandardMail {
    pub fn new(transport: Arc<dyn MailTransport>) -> Self {
        Self { transport }
    }

    /// Standard mail over a host's channel.
    pub fn over(channel: Arc<dyn NotificationChannel>) -> Self {
        Self::new(Arc::new(HostChannel(channel)))
    }
}

#[async_trait]
impl AuthMailDelivery for StandardMail {
    async fn deliver(&self, mail: &OwedMail) -> Result<String, MailError> {
        let message = render(mail);
        let channel = self
            .transport
            .channel()
            .await
            .map_err(MailError::Unavailable)?;
        let recipient = Recipient {
            profile_id: String::new(),
            email: Some(mail.destination.clone()),
            phone: None,
            push_endpoint: None,
            device_token: None,
            locale: "en".into(),
        };
        Ok(channel.deliver(&recipient, &message).await?.message_id)
    }
}

/// The standard message of `mail`.
pub(super) fn render(mail: &OwedMail) -> RenderedMessage {
    let secret = mail.secret.expose_secret();
    let minutes = mail.expires_minutes;
    let (subject, body, body_text, event_type) = match mail.message {
        AuthMessage::MagicLink => (
            "Your sign-in link".to_owned(),
            format!(
                "<h2>Sign in</h2>\
                 <p>A sign-in link was requested for your account.</p>\
                 <p><a href=\"{link}\">Sign in</a></p>\
                 <p>The link works once and expires in {minutes} minutes. If you did not ask for it, ignore this message.</p>",
                link = html(secret),
            ),
            format!(
                "Sign in\n\n\
                 A sign-in link was requested for your account.\n\
                 Sign in: {secret}\n\n\
                 The link works once and expires in {minutes} minutes. If you did not ask for it, ignore this message."
            ),
            event_types::MAGIC_LINK_REQUESTED,
        ),
        AuthMessage::SignInCode => code(secret, minutes, "sign in"),
        AuthMessage::RegistrationCode => code(
            secret,
            minutes,
            "confirm your email address and finish creating your account",
        ),
        AuthMessage::PasswordReset => (
            "Reset your password".to_owned(),
            format!(
                "<h2>Reset your password</h2>\
                 <p>A password reset was requested for your account.</p>\
                 <p><a href=\"{link}\">Choose a new password</a></p>\
                 <p>The link works once and expires in {minutes} minutes. If you did not ask for this, ignore this message: your password stays as it is.</p>",
                link = html(secret),
            ),
            format!(
                "Reset your password\n\n\
                 A password reset was requested for your account.\n\
                 Choose a new password: {secret}\n\n\
                 The link works once and expires in {minutes} minutes. If you did not ask for this, ignore this message: your password stays as it is."
            ),
            event_types::PASSWORD_RESET_REQUESTED,
        ),
    };
    RenderedMessage {
        subject: Some(subject),
        body,
        body_text: Some(body_text),
        priority: NotificationPriority::Transactional,
        event_type: event_type.to_owned(),
    }
}

/// A one-time code's message; `purpose` names the flow that asked for it.
fn code(code: &str, minutes: i64, purpose: &str) -> (String, String, String, &'static str) {
    (
        format!("Your code: {code}"),
        format!(
            "<h2>Your code</h2>\
             <p>Use this code to {purpose}:</p>\
             <p style=\"font-size:24px;letter-spacing:4px\"><strong>{code}</strong></p>\
             <p>It works once and expires in {minutes} minutes. If you did not ask for it, ignore this message.</p>",
            code = html(code),
        ),
        format!(
            "Your code\n\n\
             Use this code to {purpose}: {code}\n\n\
             It works once and expires in {minutes} minutes. If you did not ask for it, ignore this message."
        ),
        event_types::OTP_REQUESTED,
    )
}

/// `text` as HTML text or a quoted attribute value: a link's query joins
/// its pairs with `&`, which HTML reads as the start of a reference.
fn html(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests;
