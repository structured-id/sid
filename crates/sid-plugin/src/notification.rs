// SPDX-License-Identifier: AGPL-3.0-only
//! Notification channel plugin traits for sid-notify.
//!
//! All external delivery (email, SMS, push, webhooks) goes through
//! sid-notify which uses `NotificationChannel` plugins for each transport.
//!
//! CE channels: Email (SMTP), Webhook (HTTP+HMAC), Web Push (VAPID).
//! EE channels: SMS (Twilio/Vonage), Mobile Push (FCM/APNs), Custom.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A notification recipient with contact details per channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    /// Profile ID of the recipient.
    pub profile_id: String,

    /// Email address (for email channel).
    pub email: Option<String>,

    /// Phone number in E.164 format (for SMS channel).
    pub phone: Option<String>,

    /// Push subscription endpoint (for Web Push).
    pub push_endpoint: Option<String>,

    /// Device token (for FCM/APNs).
    pub device_token: Option<String>,

    /// Preferred locale (BCP 47 language tag).
    pub locale: String,
}

/// A rendered message ready for delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedMessage {
    /// Message subject/title (for email, push).
    pub subject: Option<String>,

    /// Message body (HTML for email, plain text for SMS, etc.).
    pub body: String,

    /// Plain text alternative (for email multipart).
    pub body_text: Option<String>,

    /// Notification priority.
    pub priority: NotificationPriority,

    /// Original event type that triggered this notification.
    pub event_type: String,
}

/// Notification priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotificationPriority {
    /// Security-critical: cannot be disabled by recipient (new login, password change).
    Critical,
    /// Transactional: follows the action (OTP delivery, email verification).
    Transactional,
    /// Informational: respects opt-out (expiry reminders, product updates).
    Informational,
}

/// Receipt from a successful delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// Provider-assigned message ID.
    pub message_id: String,

    /// Channel that delivered the message.
    pub channel: String,

    /// When the delivery was attempted.
    pub timestamp: DateTime<Utc>,

    /// Provider name (e.g., "smtp", "twilio", "fcm").
    pub provider: String,
}

/// Delivery status for tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    /// Accepted by provider (not yet delivered to recipient).
    Accepted,
    /// Confirmed delivered to recipient.
    Delivered,
    /// Delivery failed permanently.
    Failed,
    /// Recipient bounced (invalid email, etc.).
    Bounced,
    /// Delivery pending (provider processing).
    Pending,
}

/// Channel health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelHealth {
    /// Whether the channel is operational.
    pub healthy: bool,

    /// Optional status message.
    pub message: Option<String>,

    /// Last successful delivery timestamp.
    pub last_success: Option<DateTime<Utc>>,
}

/// Error during notification delivery.
#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error("delivery failed: {0}")]
    Failed(String),

    /// The request reached the provider but its reply did not (a timeout
    /// after sending); the message may have been accepted.
    #[error("delivery outcome unknown: {0}")]
    Ambiguous(String),

    /// The provider refused the message permanently; sending it again
    /// cannot succeed.
    #[error("delivery rejected: {0}")]
    Rejected(String),

    #[error("recipient not reachable via this channel")]
    NotReachable,

    #[error("rate limited by provider")]
    RateLimited,

    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("channel not configured")]
    NotConfigured,

    #[error("internal error: {0}")]
    Internal(String),
}

/// Plugin trait for notification delivery channels.
///
/// Implement this to add delivery channels to sid-notify.
/// CE: Email (SMTP), Webhook, Web Push.
/// EE: SMS, Mobile Push, Custom.
#[async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Channel identifier (e.g., "email", "sms", "webhook", "web_push").
    fn channel_id(&self) -> &str;

    /// Deliver a notification to a recipient.
    async fn deliver(
        &self,
        recipient: &Recipient,
        message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError>;

    /// Check delivery status (if channel supports tracking).
    async fn delivery_status(
        &self,
        receipt: &DeliveryReceipt,
    ) -> Result<DeliveryStatus, DeliveryError> {
        // Default: accepted (no tracking support)
        let _ = receipt;
        Ok(DeliveryStatus::Accepted)
    }

    /// Health check for this channel.
    async fn health(&self) -> Result<ChannelHealth, DeliveryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delivery_error_display() {
        assert_eq!(
            DeliveryError::Failed("timeout".into()).to_string(),
            "delivery failed: timeout"
        );
        assert_eq!(
            DeliveryError::NotReachable.to_string(),
            "recipient not reachable via this channel"
        );
        assert_eq!(
            DeliveryError::RateLimited.to_string(),
            "rate limited by provider"
        );
        assert_eq!(
            DeliveryError::NotConfigured.to_string(),
            "channel not configured"
        );
    }

    #[test]
    fn test_notification_priority_serde() {
        let critical = NotificationPriority::Critical;
        let json = serde_json::to_string(&critical).unwrap();
        assert_eq!(json, "\"critical\"");

        let deserialized: NotificationPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, NotificationPriority::Critical);
    }

    #[test]
    fn test_delivery_status_serde() {
        for status in [
            DeliveryStatus::Accepted,
            DeliveryStatus::Delivered,
            DeliveryStatus::Failed,
            DeliveryStatus::Bounced,
            DeliveryStatus::Pending,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: DeliveryStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_recipient_serde() {
        let recipient = Recipient {
            profile_id: "prof_123".into(),
            email: Some("alice@sid.example.com".into()),
            phone: Some("+15551234567".into()),
            push_endpoint: None,
            device_token: None,
            locale: "en".into(),
        };

        let json = serde_json::to_string(&recipient).unwrap();
        let deserialized: Recipient = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.profile_id, "prof_123");
        assert_eq!(deserialized.email.as_deref(), Some("alice@sid.example.com"));
    }

    #[test]
    fn test_rendered_message_serde() {
        let msg = RenderedMessage {
            subject: Some("New login detected".into()),
            body: "<h1>New login</h1>".into(),
            body_text: Some("New login from unknown device".into()),
            priority: NotificationPriority::Critical,
            event_type: "sid.session.created.v1".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: RenderedMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.priority, NotificationPriority::Critical);
    }

    #[test]
    fn test_channel_health_serde() {
        let health = ChannelHealth {
            healthy: true,
            message: None,
            last_success: Some(Utc::now()),
        };

        let json = serde_json::to_string(&health).unwrap();
        let deserialized: ChannelHealth = serde_json::from_str(&json).unwrap();
        assert!(deserialized.healthy);
    }

    #[tokio::test]
    async fn test_notification_channel_object_safety() {
        struct DummyChannel;

        #[async_trait]
        impl NotificationChannel for DummyChannel {
            fn channel_id(&self) -> &str {
                "test"
            }

            async fn deliver(
                &self,
                _recipient: &Recipient,
                _message: &RenderedMessage,
            ) -> Result<DeliveryReceipt, DeliveryError> {
                Ok(DeliveryReceipt {
                    message_id: "msg_001".into(),
                    channel: "test".into(),
                    timestamp: Utc::now(),
                    provider: "dummy".into(),
                })
            }

            async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
                Ok(ChannelHealth {
                    healthy: true,
                    message: None,
                    last_success: None,
                })
            }
        }

        let channel: Box<dyn NotificationChannel> = Box::new(DummyChannel);
        assert_eq!(channel.channel_id(), "test");

        let health = channel.health().await.unwrap();
        assert!(health.healthy);
    }

    #[test]
    fn test_notification_channel_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        struct DummyChannel;
        #[async_trait]
        impl NotificationChannel for DummyChannel {
            fn channel_id(&self) -> &str {
                "test"
            }
            async fn deliver(
                &self,
                _: &Recipient,
                _: &RenderedMessage,
            ) -> Result<DeliveryReceipt, DeliveryError> {
                unimplemented!()
            }
            async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
                unimplemented!()
            }
        }

        assert_send_sync::<DummyChannel>();
    }
}
