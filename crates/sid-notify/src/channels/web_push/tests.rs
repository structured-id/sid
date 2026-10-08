use super::*;
use sid_plugin::notification::NotificationPriority;

fn test_config() -> VapidConfig {
    VapidConfig {
        subject: "mailto:admin@sid.example.com".into(),
        public_key: "BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkOs7O6KZKrCf-LPn1FFe0KlvTKP5eo_1dbGa0MnR4".into(),
        private_key: "Dt1CLgQlkiaA-tmCkATyKZeoF1-Gtw1-gdEP6pOCqj4".into(),
    }
}

fn test_recipient() -> Recipient {
    Recipient {
        profile_id: "prof_123".into(),
        email: None,
        phone: None,
        push_endpoint: Some("https://fcm.googleapis.com/fcm/send/test-endpoint".into()),
        device_token: None,
        locale: "en".into(),
    }
}

fn test_message() -> RenderedMessage {
    RenderedMessage {
        subject: Some("New login".into()),
        body: "A new login was detected".into(),
        body_text: None,
        priority: NotificationPriority::Informational,
        event_type: "sid.session.created.v1".into(),
    }
}

/// Nothing is sent to the push service, so no receipt may be issued: a
/// receipt would mark the notification delivered while the browser never
/// received it.
#[tokio::test]
async fn test_web_push_does_not_report_unsent_delivery() {
    let channel = WebPushChannel::new(test_config());
    let err = channel
        .deliver(&test_recipient(), &test_message())
        .await
        .unwrap_err();
    assert!(matches!(err, DeliveryError::NotConfigured), "{err:?}");
}

#[tokio::test]
async fn test_web_push_no_endpoint() {
    let channel = WebPushChannel::new(test_config());
    let recipient = Recipient {
        push_endpoint: None,
        ..test_recipient()
    };

    let err = channel
        .deliver(&recipient, &test_message())
        .await
        .unwrap_err();
    assert!(matches!(err, DeliveryError::NotReachable));
}

#[tokio::test]
async fn test_web_push_empty_endpoint() {
    let channel = WebPushChannel::new(test_config());
    let recipient = Recipient {
        push_endpoint: Some(String::new()),
        ..test_recipient()
    };

    let err = channel
        .deliver(&recipient, &test_message())
        .await
        .unwrap_err();
    assert!(matches!(err, DeliveryError::InvalidRecipient(_)));
}

/// A channel that cannot deliver does not report itself healthy, even with
/// VAPID keys configured.
#[tokio::test]
async fn test_web_push_health_reports_unavailable_delivery() {
    let channel = WebPushChannel::new(test_config());
    let health = channel.health().await.unwrap();
    assert!(!health.healthy);
}

#[tokio::test]
async fn test_web_push_health_not_configured() {
    let channel = WebPushChannel::new(VapidConfig {
        subject: String::new(),
        public_key: String::new(),
        private_key: String::new(),
    });
    let health = channel.health().await.unwrap();
    assert!(!health.healthy);
}

#[test]
fn test_web_push_channel_id() {
    let channel = WebPushChannel::new(test_config());
    assert_eq!(channel.channel_id(), "web_push");
}

#[test]
fn test_web_push_public_key() {
    let channel = WebPushChannel::new(test_config());
    assert!(!channel.public_key().is_empty());
}
