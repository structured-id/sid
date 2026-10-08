use super::*;
use sid_core::models::event::event_types;

#[tokio::test]
async fn test_publish_to_subscriber() {
    let bus = InProcessEventBus::new();

    let filter = EventFilter {
        event_types: vec![event_types::USER_CREATED.to_string()],
        ..Default::default()
    };
    let mut rx = bus.subscribe(filter).await.unwrap();

    let event = Event::new("test", event_types::USER_CREATED).with_subject("profile/123");
    bus.publish(event).await.unwrap();

    let received = rx.recv().await.unwrap();
    assert_eq!(received.event_type, event_types::USER_CREATED);
    assert_eq!(received.subject.as_deref(), Some("profile/123"));
}

#[tokio::test]
async fn test_publish_filtered_out() {
    let bus = InProcessEventBus::new();

    let filter = EventFilter {
        event_types: vec![event_types::USER_CREATED.to_string()],
        ..Default::default()
    };
    let mut rx = bus.subscribe(filter).await.unwrap();

    // Publish a different event type
    let event = Event::new("test", event_types::SESSION_CREATED);
    bus.publish(event).await.unwrap();

    // Should not receive anything
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn test_wildcard_subscription() {
    let bus = InProcessEventBus::new();

    let filter = EventFilter {
        event_types: vec!["sid.user.*".to_string()],
        ..Default::default()
    };
    let mut rx = bus.subscribe(filter).await.unwrap();

    bus.publish(Event::new("test", event_types::USER_CREATED))
        .await
        .unwrap();
    bus.publish(Event::new("test", event_types::USER_LOCKED))
        .await
        .unwrap();
    bus.publish(Event::new("test", event_types::SESSION_CREATED))
        .await
        .unwrap();

    // Should receive 2 user events, not the session event
    let e1 = rx.recv().await.unwrap();
    assert_eq!(e1.event_type, event_types::USER_CREATED);

    let e2 = rx.recv().await.unwrap();
    assert_eq!(e2.event_type, event_types::USER_LOCKED);

    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn test_multiple_subscribers() {
    let bus = InProcessEventBus::new();

    let filter_all = EventFilter::default();
    let filter_security = EventFilter {
        event_types: vec!["sid.security.*".to_string()],
        ..Default::default()
    };

    let mut rx_all = bus.subscribe(filter_all).await.unwrap();
    let mut rx_security = bus.subscribe(filter_security).await.unwrap();

    bus.publish(Event::new("test", event_types::USER_CREATED))
        .await
        .unwrap();
    bus.publish(Event::new("test", event_types::SECURITY_BRUTE_FORCE))
        .await
        .unwrap();

    // All-subscriber gets both
    rx_all.recv().await.unwrap();
    rx_all.recv().await.unwrap();

    // Security-subscriber gets only security event
    let sec = rx_security.recv().await.unwrap();
    assert_eq!(sec.event_type, event_types::SECURITY_BRUTE_FORCE);
    assert!(rx_security.try_recv().is_err());
}

#[tokio::test]
async fn test_closed_subscriber_cleaned_up() {
    let bus = InProcessEventBus::new();

    let filter = EventFilter::default();
    let rx = bus.subscribe(filter).await.unwrap();

    // Drop receiver — channel closes
    drop(rx);

    // Publishing should not error (just cleans up)
    bus.publish(Event::new("test", event_types::USER_CREATED))
        .await
        .unwrap();

    // Verify subscriber was removed
    let subs = bus.subscribers.lock().unwrap();
    assert!(subs.is_empty());
}

/// A subscriber that stops reading holds at most its buffer: once full it
/// is dropped and its receiver ends after the buffered events, while other
/// subscribers keep receiving. It used to grow without bound.
#[tokio::test]
async fn test_lagging_subscriber_is_dropped() {
    let bus = InProcessEventBus::new();
    let mut lagging = bus.subscribe(EventFilter::default()).await.unwrap();
    let mut reading = bus.subscribe(EventFilter::default()).await.unwrap();

    for _ in 0..=SUBSCRIPTION_CAPACITY {
        bus.publish(Event::new("test", event_types::USER_CREATED))
            .await
            .unwrap();
        reading.recv().await.unwrap();
    }

    let mut buffered = 0;
    while lagging.recv().await.is_some() {
        buffered += 1;
    }
    assert_eq!(buffered, SUBSCRIPTION_CAPACITY);

    bus.publish(Event::new("test", event_types::USER_LOCKED))
        .await
        .unwrap();
    assert_eq!(
        reading.recv().await.unwrap().event_type,
        event_types::USER_LOCKED
    );
    assert_eq!(bus.subscribers.lock().unwrap().len(), 1);
}

/// A bus without history says so instead of answering an empty history.
#[tokio::test]
async fn test_replay_unsupported_is_an_error() {
    let bus = InProcessEventBus::new();
    let err = bus
        .replay(chrono::Utc::now(), None, EventFilter::default())
        .await
        .unwrap_err();
    assert!(matches!(err, EventBusError::ReplayUnsupported), "{err:?}");
}

#[tokio::test]
async fn test_health_check() {
    let bus = InProcessEventBus::new();
    bus.health_check().await.unwrap();
}

#[tokio::test]
async fn test_event_bus_object_safety() {
    let bus: Box<dyn EventBus> = Box::new(InProcessEventBus::new());
    bus.health_check().await.unwrap();

    let mut rx = bus.subscribe(EventFilter::default()).await.unwrap();
    bus.publish(Event::new("test", "test.event.v1"))
        .await
        .unwrap();
    let event = rx.recv().await.unwrap();
    assert_eq!(event.event_type, "test.event.v1");
}

#[tokio::test]
async fn test_event_bus_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InProcessEventBus>();
}

#[tokio::test]
async fn test_publish_with_no_subscribers() {
    let bus = InProcessEventBus::new();
    // Should not error
    bus.publish(Event::new("test", event_types::USER_CREATED))
        .await
        .unwrap();
}
