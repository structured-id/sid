// SPDX-License-Identifier: AGPL-3.0-only
//! This server's rendering and sending of the authentication mails the
//! engine owes ([`sid::auth_mail`]): its CE templates, and the email provider
//! read from the installation's stored settings at every attempt, so all
//! replicas send alike and a change applies to the next attempt.

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use sid::auth_mail::{AuthMailDelivery, AuthMessage, MailError, OwedMail};
use sid::email_provider::ProviderError;
use sid_core::models::event::{Event, event_types};
use sid_notify::TemplateEngine;
use sid_plugin::notification::{NotificationChannel, NotificationPriority, Recipient};
use sid_plugin::storage::StorageBackend;

use crate::grpc::realm_service::email_channel;

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
        // work waiting for it until its secret expires.
        let cfg = sid::email_provider::stored(self.storage.as_ref(), self.keys.as_ref())
            .await
            .map_err(|e: ProviderError| e.to_string())?
            .ok_or("no email provider is configured")?;
        email_channel(&cfg)
    }
}

/// Authentication mail rendered with the CE templates and sent over
/// `transport`. Rendered per attempt and dropped with it: no copy of the
/// secret is stored anywhere but its sealed session.
pub struct TemplatedMail {
    transport: Arc<dyn MailTransport>,
    templates: TemplateEngine,
}

impl TemplatedMail {
    pub fn new(transport: Arc<dyn MailTransport>) -> Self {
        Self {
            transport,
            templates: TemplateEngine::with_default_ce_templates(),
        }
    }
}

#[async_trait]
impl AuthMailDelivery for TemplatedMail {
    async fn deliver(&self, mail: &OwedMail) -> Result<String, MailError> {
        let secret = mail.secret.expose_secret();
        let (template, event_type, data) = match mail.message {
            AuthMessage::MagicLink => (
                "magic_link",
                event_types::MAGIC_LINK_REQUESTED,
                serde_json::json!({ "link": secret, "expires_minutes": mail.expires_minutes }),
            ),
            AuthMessage::SignInCode => (
                "otp",
                event_types::OTP_REQUESTED,
                serde_json::json!({
                    "code": secret,
                    "expires_minutes": mail.expires_minutes,
                    "purpose": "sign in",
                }),
            ),
            AuthMessage::PasswordReset => (
                "password_reset",
                event_types::PASSWORD_RESET_REQUESTED,
                serde_json::json!({ "link": secret, "expires_minutes": mail.expires_minutes }),
            ),
        };
        let event = Event::new("sid-identity", event_type).with_data(data);
        let message = self
            .templates
            .render(template, &event, NotificationPriority::Transactional)
            .map_err(|e| MailError::Render(format!("the {template} mail: {e}")))?;
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

#[cfg(test)]
mod tests;
