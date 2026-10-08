use super::*;
use sid_core::models::event::event_types;
use sid_core::models::{Profile, Session};
use sid_plugin::event_bus::InProcessEventBus;
use tokio_stream::StreamExt;

fn test_jwt() -> Arc<JwtService> {
    Arc::new(
        JwtService::new(
            include_bytes!("../../../../sid-authn/tests/fixtures/test_ed25519_private.pem"),
            include_bytes!("../../../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
            "https://sid.example.com".to_string(),
        )
        .expect("JWT creation failed"),
    )
}

fn service(bus: Arc<dyn EventBus>) -> EventStreamServiceImpl {
    EventStreamServiceImpl::new(
        bus,
        test_jwt(),
        Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        )),
    )
}

fn token_for(profile: &Profile) -> String {
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    test_jwt()
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            profile,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap()
}

fn with_token<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// A request from an administrator.
fn admin<T>(msg: T) -> Request<T> {
    let mut profile = Profile::new(Some("events-admin"));
    profile.roles = vec!["admin".to_string()];
    with_token(msg, &token_for(&profile))
}

#[test]
fn test_event_to_proto_basic() {
    let event = Event::new("sid-identity.test", event_types::USER_CREATED)
        .with_subject("profile/prof_123")
        .with_data(serde_json::json!({"name": "Alice"}))
        .with_sequence(42);

    let proto = event_to_proto(&event).unwrap();

    assert_eq!(proto.id, event.id);
    assert_eq!(proto.source, "sid-identity.test");
    assert_eq!(proto.spec_version, "1.0");
    assert_eq!(proto.r#type, "sid.user.created.v1");
    assert_eq!(proto.subject, "profile/prof_123");
    assert_eq!(proto.datacontenttype, "application/json");
    assert_eq!(proto.sequence, 42);
    assert!(proto.time.is_some());

    // Data should be JSON bytes.
    let data: serde_json::Value = serde_json::from_slice(&proto.data).unwrap();
    assert_eq!(data["name"], "Alice");
}

#[test]
fn test_event_to_proto_null_data() {
    let event = Event::new("src", "test.v1");
    let proto = event_to_proto(&event).unwrap();
    assert!(proto.data.is_empty());
}

#[test]
fn test_event_to_proto_no_subject() {
    let event = Event::new("src", "test.v1");
    let proto = event_to_proto(&event).unwrap();
    assert_eq!(proto.subject, "");
}

/// Regression (#881, K21): without a token nobody subscribes to or replays the
/// event stream, which carries profile, session and provisioning events.
#[tokio::test]
async fn test_stream_requires_a_token() {
    let svc = service(Arc::new(InProcessEventBus::new()));
    let err = svc
        .subscribe(Request::new(SubscribeRequest {
            event_types: vec!["sid.>".to_string()],
            filters: Default::default(),
        }))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let err = svc
        .replay(Request::new(ReplayRequest {
            from: Some(prost_types::Timestamp {
                seconds: 0,
                nanos: 0,
            }),
            to: None,
            event_types: vec![],
        }))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// Regression (#881, K21): a signed-in user without the administrator role
/// cannot read other users' events.
#[tokio::test]
async fn test_stream_refuses_a_non_admin() {
    let svc = service(Arc::new(InProcessEventBus::new()));
    let token = token_for(&Profile::new(Some("mallory")));
    let err = svc
        .subscribe(with_token(
            SubscribeRequest {
                event_types: vec!["sid.user.*".to_string()],
                filters: Default::default(),
            },
            &token,
        ))
        .await
        .expect_err("not an administrator");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_subscribe_with_in_process_bus() {
    let bus = Arc::new(InProcessEventBus::new());
    let svc = service(bus.clone());

    let request = admin(SubscribeRequest {
        event_types: vec!["sid.user.*".to_string()],
        filters: Default::default(),
    });

    let response = svc.subscribe(request).await.unwrap();
    let mut stream = response.into_inner();

    // Publish an event.
    let event = Event::new("test", event_types::USER_CREATED)
        .with_subject("profile/p1")
        .with_data(serde_json::json!({"method": "password"}));
    bus.publish(event.clone()).await.unwrap();

    // Should receive it via the stream.
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(received.r#type, "sid.user.created.v1");
    assert_eq!(received.spec_version, "1.0");
    assert_eq!(received.subject, "profile/p1");
}

#[tokio::test]
async fn test_subscribe_filters_events() {
    let bus = Arc::new(InProcessEventBus::new());
    let svc = service(bus.clone());

    let request = admin(SubscribeRequest {
        event_types: vec!["sid.security.*".to_string()],
        filters: Default::default(),
    });

    let response = svc.subscribe(request).await.unwrap();
    let mut stream = response.into_inner();

    // Publish a user event (should be filtered out).
    bus.publish(Event::new("test", event_types::USER_CREATED))
        .await
        .unwrap();

    // Publish a security event (should pass).
    bus.publish(Event::new("test", event_types::SECURITY_BRUTE_FORCE))
        .await
        .unwrap();

    let received = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(received.r#type, "sid.security.brute_force.v1");
}

/// A deployment without event history says so: an empty replay used to be
/// indistinguishable from "nothing happened".
#[tokio::test]
async fn test_replay_without_history_is_refused() {
    let svc = service(Arc::new(InProcessEventBus::new()));

    let request = admin(ReplayRequest {
        from: Some(prost_types::Timestamp {
            seconds: 0,
            nanos: 0,
        }),
        to: None,
        event_types: vec![],
    });

    let err = svc.replay(request).await.expect_err("no history");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(reason(&err).as_deref(), Some("FEATURE_NOT_CONFIGURED"));
}

/// `ErrorInfo.reason` of a refusal.
fn reason(status: &tonic::Status) -> Option<String> {
    sid_core::grpc_error::extract_error_info(status).map(|(reason, _, _)| reason)
}

/// A bus whose history is `count` events.
struct HistoryBus {
    count: usize,
}

#[tonic::async_trait]
impl EventBus for HistoryBus {
    async fn publish(&self, _: Event) -> sid_plugin::event_bus::EventBusResult<()> {
        Ok(())
    }
    async fn subscribe(
        &self,
        _: EventFilter,
    ) -> sid_plugin::event_bus::EventBusResult<mpsc::Receiver<Event>> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(rx)
    }
    async fn replay(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: Option<chrono::DateTime<chrono::Utc>>,
        _: EventFilter,
    ) -> sid_plugin::event_bus::EventBusResult<mpsc::Receiver<Event>> {
        let (tx, rx) = mpsc::channel(16);
        let count = self.count;
        tokio::spawn(async move {
            for _ in 0..count {
                if tx
                    .send(Event::new("history", event_types::USER_CREATED))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(rx)
    }
    async fn health_check(&self) -> sid_plugin::event_bus::EventBusResult<()> {
        Ok(())
    }
}

fn replay_from_epoch() -> ReplayRequest {
    ReplayRequest {
        from: Some(prost_types::Timestamp {
            seconds: 0,
            nanos: 0,
        }),
        to: None,
        event_types: vec![],
    }
}

/// A history larger than one replay may deliver ends with
/// `RESOURCE_EXHAUSTED` after the bound, never as a silently complete stream.
#[tokio::test]
async fn test_replay_window_is_bounded() {
    let svc = service(Arc::new(HistoryBus {
        count: MAX_REPLAY_EVENTS + 1,
    }));
    let mut stream = svc
        .replay(admin(replay_from_epoch()))
        .await
        .unwrap()
        .into_inner();

    let mut delivered = 0;
    let last = loop {
        match stream.next().await.expect("stream ends with a status") {
            Ok(_) => delivered += 1,
            Err(status) => break status,
        }
    };
    assert_eq!(delivered, MAX_REPLAY_EVENTS);
    assert_eq!(last.code(), tonic::Code::ResourceExhausted);
    assert_eq!(reason(&last).as_deref(), Some("QUOTA_EXCEEDED"));
    // Repeating the same window cannot help, so no retry delay is offered.
    assert!(sid_core::grpc_error::extract_retry_delay(&last).is_none());
}

/// A window within the bound is delivered whole.
#[tokio::test]
async fn test_replay_small_window_is_whole() {
    let svc = service(Arc::new(HistoryBus { count: 3 }));
    let events: Vec<_> = svc
        .replay(admin(replay_from_epoch()))
        .await
        .unwrap()
        .into_inner()
        .collect()
        .await;
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(Result::is_ok));
}

/// A timestamp the protobuf cannot mean, or a window ending before it
/// starts, is refused; `from` used to become "now" when unreadable.
#[tokio::test]
async fn test_replay_invalid_window_is_refused() {
    let svc = service(Arc::new(HistoryBus { count: 1 }));
    let bad_from = ReplayRequest {
        from: Some(prost_types::Timestamp {
            seconds: 0,
            nanos: -1,
        }),
        ..replay_from_epoch()
    };
    let backwards = ReplayRequest {
        from: Some(prost_types::Timestamp {
            seconds: 100,
            nanos: 0,
        }),
        to: Some(prost_types::Timestamp {
            seconds: 50,
            nanos: 0,
        }),
        event_types: vec![],
    };
    for request in [bad_from, backwards] {
        let err = svc
            .replay(admin(request))
            .await
            .expect_err("invalid window");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(reason(&err).as_deref(), Some("INVALID_FIELD_VALUE"));
    }
}

/// One administrator holds a bounded number of open streams; a closed
/// stream frees its place.
#[tokio::test]
async fn test_streams_per_caller_are_bounded() {
    let svc = service(Arc::new(InProcessEventBus::new()));
    let mut profile = Profile::new(Some("stream-admin"));
    profile.roles = vec!["admin".to_string()];
    let token = token_for(&profile);
    let open = || {
        svc.subscribe(with_token(
            SubscribeRequest {
                event_types: vec!["sid.user.*".to_string()],
                filters: Default::default(),
            },
            &token,
        ))
    };

    let mut streams = Vec::new();
    for _ in 0..MAX_STREAMS_PER_CALLER {
        streams.push(open().await.unwrap());
    }
    let err = open().await.expect_err("limit reached");
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert_eq!(reason(&err).as_deref(), Some("QUOTA_EXCEEDED"));
    // Streams end when their clients leave, so a retry later can succeed.
    assert!(sid_core::grpc_error::extract_retry_delay(&err).is_some());

    drop(streams.pop());
    // No event arrives: the forwarder notices the closed stream by itself.
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if svc.per_caller.get(&profile.id).map(|n| *n) == Some(MAX_STREAMS_PER_CALLER - 1) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("closed stream released");
    open().await.expect("a freed place is reusable");
}

#[tokio::test]
async fn test_replay_requires_from_timestamp() {
    let svc = service(Arc::new(InProcessEventBus::new()));

    // Missing `from` → InvalidArgument.
    let request = admin(ReplayRequest {
        from: None,
        to: None,
        event_types: vec![],
    });

    let err = svc.replay(request).await.expect_err("missing from");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&err).as_deref(), Some("REQUIRED_FIELD_MISSING"));
}
