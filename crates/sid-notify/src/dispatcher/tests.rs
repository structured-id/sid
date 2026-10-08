// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::template::NotificationTemplate;
use async_trait::async_trait;
use chrono::Utc;
use sid_core::models::event::event_types;
use sid_plugin::notification::ChannelHealth;

/// Test channel that accepts or refuses every message.
struct TestChannel {
    id: &'static str,
    accept: bool,
}

#[async_trait]
impl NotificationChannel for TestChannel {
    fn channel_id(&self) -> &str {
        self.id
    }

    async fn deliver(
        &self,
        _recipient: &Recipient,
        _message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        if !self.accept {
            return Err(DeliveryError::Failed("test failure".into()));
        }
        Ok(DeliveryReceipt {
            message_id: "m-1".into(),
            channel: self.id.into(),
            timestamp: Utc::now(),
            provider: "test".into(),
        })
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        Ok(ChannelHealth {
            healthy: self.accept,
            message: None,
            last_success: None,
        })
    }
}

fn recipient() -> Recipient {
    Recipient {
        profile_id: "prof_123".into(),
        email: Some("alice@sid.example.com".into()),
        phone: None,
        push_endpoint: None,
        device_token: None,
        locale: "en".into(),
    }
}

fn dispatcher() -> (NotificationDispatcher, Arc<RwLock<TemplateEngine>>) {
    let engine = Arc::new(RwLock::new(TemplateEngine::with_default_ce_templates()));
    let mut dispatcher = NotificationDispatcher::new(Arc::clone(&engine));
    dispatcher.register_channel(Arc::new(TestChannel {
        id: "email",
        accept: true,
    }));
    dispatcher.register_channel(Arc::new(TestChannel {
        id: "webhook",
        accept: false,
    }));
    (dispatcher, engine)
}

/// Rendering reads the shared engine, so a template an administrator
/// customized is the one delivered.
#[tokio::test]
async fn test_render_uses_customized_template() {
    let (dispatcher, engine) = dispatcher();
    engine.write().await.register(NotificationTemplate {
        name: "security_alert".into(),
        subject: Some("Custom alert".into()),
        body_html: "<p>custom</p>".into(),
        body_text: "custom".into(),
        default_priority: NotificationPriority::Critical,
    });
    let event = Event::new("src", event_types::SECURITY_BRUTE_FORCE);
    let message = dispatcher
        .render("security_alert", &event, NotificationPriority::Critical)
        .await
        .unwrap();
    assert_eq!(message.subject.as_deref(), Some("Custom alert"));
}

/// An unknown template is a render error, not an empty message.
#[tokio::test]
async fn test_render_unknown_template_fails() {
    let (dispatcher, _) = dispatcher();
    let event = Event::new("src", event_types::SECURITY_BRUTE_FORCE);
    let err = dispatcher
        .render("no_such_template", &event, NotificationPriority::Critical)
        .await
        .unwrap_err();
    assert!(matches!(err, TemplateError::NotFound(_)));
}

/// Delivery goes through the named channel; an unregistered channel is
/// reported as not configured, and a channel's error is passed through.
#[tokio::test]
async fn test_deliver_to_channel() {
    let (dispatcher, _) = dispatcher();
    let event = Event::new("src", event_types::SECURITY_BRUTE_FORCE);
    let message = dispatcher
        .render("security_alert", &event, NotificationPriority::Critical)
        .await
        .unwrap();

    let receipt = dispatcher
        .deliver_to_channel("email", &recipient(), &message)
        .await
        .unwrap();
    assert_eq!(receipt.channel, "email");
    assert!(matches!(
        dispatcher
            .deliver_to_channel("sms", &recipient(), &message)
            .await,
        Err(DeliveryError::NotConfigured)
    ));
    assert!(matches!(
        dispatcher
            .deliver_to_channel("webhook", &recipient(), &message)
            .await,
        Err(DeliveryError::Failed(_))
    ));
}

#[tokio::test]
async fn test_health_check_and_channel_ids() {
    let (dispatcher, _) = dispatcher();
    let health = dispatcher.health_check().await;
    assert_eq!(health.get("email"), Some(&true));
    assert_eq!(health.get("webhook"), Some(&false));
    let mut ids = dispatcher.channel_ids();
    ids.sort();
    assert_eq!(ids, vec!["email", "webhook"]);
}
