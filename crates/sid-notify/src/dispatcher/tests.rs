// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use async_trait::async_trait;
use chrono::Utc;
use sid_plugin::notification::{ChannelHealth, NotificationPriority};

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

fn dispatcher() -> NotificationDispatcher {
    let mut dispatcher = NotificationDispatcher::new();
    dispatcher.register_channel(Arc::new(TestChannel {
        id: "email",
        accept: true,
    }));
    dispatcher.register_channel(Arc::new(TestChannel {
        id: "webhook",
        accept: false,
    }));
    dispatcher
}

/// Delivery goes through the named channel; an unregistered channel is
/// reported as not configured, and a channel's error is passed through.
#[tokio::test]
async fn test_deliver_to_channel() {
    let dispatcher = dispatcher();
    let message = RenderedMessage {
        subject: Some("Alert".into()),
        body: "<p>alert</p>".into(),
        body_text: Some("alert".into()),
        priority: NotificationPriority::Critical,
        event_type: "sid.security.brute_force.v1".into(),
    };

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
    let dispatcher = dispatcher();
    let health = dispatcher.health_check().await;
    assert_eq!(health.get("email"), Some(&true));
    assert_eq!(health.get("webhook"), Some(&false));
    let mut ids = dispatcher.channel_ids();
    ids.sort();
    assert_eq!(ids, vec!["email", "webhook"]);
}
