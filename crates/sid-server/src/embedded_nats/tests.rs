use super::*;

use sid_core::models::event::{Event, EventFilter};

#[test]
fn test_find_available_port() {
    let port = find_available_port().unwrap();
    assert!(port >= 1024);
}

/// Unset, empty and `embedded` select the bundled server (the arch default);
/// a NATS URL selects an external cluster; anything else is refused instead
/// of silently running without a bus.
#[test]
fn mode_from_setting() {
    assert_eq!(
        EventBusMode::from_setting(None).unwrap(),
        EventBusMode::Embedded
    );
    assert_eq!(
        EventBusMode::from_setting(Some("")).unwrap(),
        EventBusMode::Embedded
    );
    assert_eq!(
        EventBusMode::from_setting(Some("embedded")).unwrap(),
        EventBusMode::Embedded
    );
    assert_eq!(
        EventBusMode::from_setting(Some("nats://nats.sid.example.com:4222")).unwrap(),
        EventBusMode::External("nats://nats.sid.example.com:4222".into())
    );
    assert!(matches!(
        EventBusMode::from_setting(Some("in-process")),
        Err(EventBusStartError::InvalidSetting(_))
    ));
}

/// A configured external NATS that cannot be reached stops startup: no
/// in-process bus takes its place.
#[tokio::test]
async fn unreachable_external_nats_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let mode = EventBusMode::External("nats://127.0.0.1:1".into());
    let result = connect_event_bus(&mode, dir.path()).await;
    assert!(matches!(result, Err(EventBusStartError::Connect(_))));
}

#[test]
fn test_embedded_nats_spawn_and_stop() {
    let dir = tempfile::tempdir().unwrap();
    let (embedded, url) = EmbeddedNats::spawn(dir.path()).expect("nats-server must be installed");
    assert!(url.starts_with("nats://127.0.0.1:"));
    let addr = format!("127.0.0.1:{}", embedded.port());
    assert!(std::net::TcpStream::connect(&addr).is_ok());

    drop(embedded);
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(std::net::TcpStream::connect(&addr).is_err());
}

#[tokio::test]
async fn test_embedded_nats_event_bus_publish_subscribe() {
    let dir = tempfile::tempdir().unwrap();
    let connected = connect_event_bus(&EventBusMode::Embedded, dir.path())
        .await
        .expect("nats-server must be installed");

    let filter = EventFilter {
        event_types: vec!["sid.security.>".to_string()],
        ..Default::default()
    };
    let mut rx = connected.bus.subscribe(filter).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let event = Event::new("test", "sid.security.brute_force.v1")
        .with_subject("profile/test-123")
        .with_data(serde_json::json!({"attempts": 5}));
    connected.bus.publish(event).await.unwrap();

    let received = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .expect("timeout waiting for event")
        .expect("channel closed");
    assert_eq!(received.event_type, "sid.security.brute_force.v1");
    connected.bus.health_check().await.unwrap();
}

/// Retained events live under the data directory, so a restarted embedded
/// server can still replay what was published before the restart.
#[tokio::test]
async fn embedded_jetstream_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let since = chrono::Utc::now() - chrono::Duration::seconds(5);
    let event = Event::new("test", "sid.user.created.v1").with_subject("profile/restart");
    let id = event.id.clone();

    let first = connect_event_bus(&EventBusMode::Embedded, dir.path())
        .await
        .expect("nats-server must be installed");
    first.bus.publish(event).await.unwrap();
    drop(first);

    let second = connect_event_bus(&EventBusMode::Embedded, dir.path())
        .await
        .expect("restart");
    let mut replay = second
        .bus
        .replay(since, None, EventFilter::default())
        .await
        .expect("replay");
    let mut seen = false;
    while let Ok(Some(e)) =
        tokio::time::timeout(std::time::Duration::from_secs(2), replay.recv()).await
    {
        if e.id == id {
            seen = true;
            break;
        }
    }
    assert!(
        seen,
        "event published before the restart must be replayable"
    );
}
