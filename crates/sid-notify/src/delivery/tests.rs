// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::template::TemplateEngine;
use chrono::Utc;
use sid_authn::work_runner::{RunnerConfig, WorkRunner};
use sid_core::models::event::EventFilter;
use sid_core::models::{WorkRecord, WorkState};
use sid_plugin::InProcessEventBus;
use sid_plugin::notification::{
    ChannelHealth, DeliveryReceipt, NotificationChannel, RenderedMessage,
};
use sid_storage::sqlite::SqliteBackend;
use std::sync::Mutex;
use tokio::sync::RwLock;

/// Channel answering every delivery with a fixed result and remembering
/// what it was asked to send.
struct ScriptedChannel {
    id: &'static str,
    answer: fn() -> Result<DeliveryReceipt, DeliveryError>,
    sent: Mutex<Vec<(String, Option<String>)>>,
}

impl ScriptedChannel {
    fn new(id: &'static str, answer: fn() -> Result<DeliveryReceipt, DeliveryError>) -> Arc<Self> {
        Arc::new(Self {
            id,
            answer,
            sent: Mutex::new(Vec::new()),
        })
    }
}

fn accepted() -> Result<DeliveryReceipt, DeliveryError> {
    Ok(DeliveryReceipt {
        message_id: "m-42".into(),
        channel: "email".into(),
        timestamp: Utc::now(),
        provider: "smtp".into(),
    })
}

#[async_trait]
impl NotificationChannel for ScriptedChannel {
    fn channel_id(&self) -> &str {
        self.id
    }

    async fn deliver(
        &self,
        recipient: &Recipient,
        message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        self.sent.lock().unwrap().push((
            recipient.email.clone().unwrap_or_default(),
            message.subject.clone(),
        ));
        (self.answer)()
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        Ok(ChannelHealth {
            healthy: true,
            message: None,
            last_success: None,
        })
    }
}

async fn store() -> Arc<dyn WorkStore> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

fn dispatcher(channels: &[Arc<ScriptedChannel>]) -> Arc<NotificationDispatcher> {
    let engine = Arc::new(RwLock::new(TemplateEngine::with_default_ce_templates()));
    let mut dispatcher = NotificationDispatcher::new(engine);
    for channel in channels {
        dispatcher.register_channel(Arc::clone(channel) as Arc<dyn NotificationChannel>);
    }
    Arc::new(dispatcher)
}

/// A security event for a profile whose address the event carries.
fn security_event() -> Event {
    Event::new("sid-server", event_types::SECURITY_BRUTE_FORCE)
        .with_subject("profile/p-1")
        .with_data(serde_json::json!({ "email": "alice@sid.example.com" }))
}

fn claimed(kind_name: &str, payload: Vec<u8>) -> ClaimedWork {
    ClaimedWork {
        id: WorkId(Uuid::now_v7()),
        kind: kind(kind_name),
        payload,
        attempt: 1,
        max_attempts: MAX_ATTEMPTS,
        generation: 1,
        expires_at: None,
    }
}

async fn record(store: &dyn WorkStore, name: &str) -> Option<WorkRecord> {
    store.get_work(stable_id(name)).await.unwrap()
}

fn route_handler(store: &Arc<dyn WorkStore>, resolver: RecipientResolver) -> RouteHandler {
    RouteHandler::new(
        RoutingTable::default_ce_rules(),
        Arc::new(resolver),
        Arc::clone(store),
        1_000,
    )
}

/// An accepted event is owned by one routing job, however often the broker
/// redelivers it; a payload that is not an event is still owned.
#[tokio::test]
async fn test_accept_event_is_idempotent_per_event() {
    let store = store().await;
    let event = security_event();
    let payload = serde_json::to_vec(&event).unwrap();
    accept_event(store.as_ref(), &payload, 10).await.unwrap();
    accept_event(store.as_ref(), &payload, 10).await.unwrap();

    let route = record(store.as_ref(), &format!("route:{}", event.id))
        .await
        .expect("accepted event has no routing job");
    assert_eq!(route.state, WorkState::Pending);
    assert_eq!(route.max_attempts, MAX_ATTEMPTS);
    let claimed = store
        .claim_work(&[kind(ROUTE)], "w", 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1, "a redelivered event was stored twice");

    accept_event(store.as_ref(), b"not json", 10).await.unwrap();
    let garbage = store
        .get_work(WorkId(Uuid::new_v5(&ID_NAMESPACE, b"not json")))
        .await
        .unwrap();
    assert!(
        garbage.is_some(),
        "an unreadable event was dropped instead of owned"
    );
}

/// A full job store refuses the event, so the broker keeps it.
#[tokio::test]
async fn test_accept_event_refused_when_full() {
    let store = store().await;
    let first = serde_json::to_vec(&security_event()).unwrap();
    let second = serde_json::to_vec(&security_event()).unwrap();
    accept_event(store.as_ref(), &first, 1).await.unwrap();
    let refused = accept_event(store.as_ref(), &second, 1).await;
    assert!(matches!(
        refused,
        Err(sid_core::Error::ResourceExhausted(_))
    ));
}

/// Routing stores one delivery per (template, channel) with a stable id; a
/// second routing attempt stores nothing new.
#[tokio::test]
async fn test_route_fans_out_once() {
    let store = store().await;
    let handler = route_handler(&store, RecipientResolver::without_identity());
    let event = security_event();
    let work = claimed(ROUTE, serde_json::to_vec(&event).unwrap());

    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("2 deliveries".into()))
    );
    handler.handle(&work).await;

    for channel in ["email", "webhook"] {
        let name = format!("deliver:{}:security_alert:{channel}", event.id);
        assert!(
            record(store.as_ref(), &name).await.is_some(),
            "{channel} missing"
        );
    }
    let deliveries = store
        .claim_work(&[kind(DELIVER)], "w", 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(
        deliveries.len(),
        2,
        "a repeated fan-out stored deliveries twice"
    );
    let job: DeliveryJob = serde_json::from_slice(&deliveries[0].payload).unwrap();
    assert_eq!(
        job.recipient.email.as_deref(),
        Some("alice@sid.example.com")
    );
}

/// Events without a rule, malformed events and an unreachable identity
/// service each end the routing job the right way.
#[tokio::test]
async fn test_route_outcomes() {
    let store = store().await;
    let handler = route_handler(&store, RecipientResolver::without_identity());
    let quiet = Event::new("src", event_types::FEDERATION_SYNC_COMPLETED);
    assert_eq!(
        handler
            .handle(&claimed(ROUTE, serde_json::to_vec(&quiet).unwrap()))
            .await,
        WorkOutcome::Done(Some("no routing rule".into()))
    );
    assert!(matches!(
        handler.handle(&claimed(ROUTE, b"{".to_vec())).await,
        WorkOutcome::Permanent(_)
    ));

    let unreachable = route_handler(
        &store,
        RecipientResolver::with_identity("http://127.0.0.1:1")
            .await
            .unwrap(),
    );
    let work = claimed(ROUTE, serde_json::to_vec(&security_event()).unwrap());
    assert!(
        matches!(unreachable.handle(&work).await, WorkOutcome::Retry(_)),
        "an unresolved recipient was not retried"
    );
}

/// A channel's answer decides the delivery: receipt kept, rejection final,
/// unknown outcome marked, transient failure retried, missing channel final.
#[tokio::test]
async fn test_deliver_outcomes() {
    let job = |channel: &str| {
        let job = DeliveryJob {
            event: security_event(),
            template: "security_alert".into(),
            priority: NotificationPriority::Critical,
            channel: channel.into(),
            recipient: Recipient {
                profile_id: "p-1".into(),
                email: Some("alice@sid.example.com".into()),
                phone: None,
                push_endpoint: None,
                device_token: None,
                locale: "en".into(),
            },
        };
        claimed(DELIVER, serde_json::to_vec(&job).unwrap())
    };
    let email = ScriptedChannel::new("email", accepted);
    let rejected = ScriptedChannel::new("rejected", || {
        Err(DeliveryError::Rejected("550 no such user".into()))
    });
    let lost = ScriptedChannel::new("lost", || {
        Err(DeliveryError::Ambiguous("timed out after DATA".into()))
    });
    let busy = ScriptedChannel::new("busy", || Err(DeliveryError::Failed("421".into())));
    let handler = DeliverHandler::new(dispatcher(&[Arc::clone(&email), rejected, lost, busy]));

    assert_eq!(
        handler.handle(&job("email")).await,
        WorkOutcome::Done(Some("smtp:email:m-42".into()))
    );
    let sent = email.sent.lock().unwrap().clone();
    assert_eq!(sent[0].0, "alice@sid.example.com");
    assert!(matches!(
        handler.handle(&job("rejected")).await,
        WorkOutcome::Permanent(_)
    ));
    assert!(matches!(
        handler.handle(&job("lost")).await,
        WorkOutcome::Ambiguous(_)
    ));
    assert!(matches!(
        handler.handle(&job("busy")).await,
        WorkOutcome::Retry(_)
    ));
    assert!(matches!(
        handler.handle(&job("sms")).await,
        WorkOutcome::Permanent(_)
    ));
}

/// End to end: an accepted event is routed and delivered by the runner; a
/// delivery that fails for good ends failed and its alert is published.
#[tokio::test]
async fn test_runner_delivers_and_alerts_dead_letters() {
    let store = store().await;
    let email = ScriptedChannel::new("email", accepted);
    let webhook = ScriptedChannel::new("webhook", || {
        Err(DeliveryError::Rejected("endpoint gone".into()))
    });
    let bus = Arc::new(InProcessEventBus::new());
    let mut alerts = bus
        .subscribe(EventFilter {
            event_types: vec![event_types::NOTIFY_DLQ.into()],
            ..Default::default()
        })
        .await
        .unwrap();
    let handlers: Vec<Arc<dyn WorkHandler>> = vec![
        Arc::new(route_handler(&store, RecipientResolver::without_identity())),
        Arc::new(DeliverHandler::new(dispatcher(&[
            Arc::clone(&email),
            webhook,
        ]))),
        Arc::new(DlqAlertHandler::new(bus.clone())),
    ];
    let config = RunnerConfig {
        concurrency: 4,
        lease: Duration::from_secs(30),
        scan_interval: Duration::from_millis(20),
    };
    let runner = WorkRunner::new(Arc::clone(&store), "w", handlers, config).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(runner.run(async move { stopped.await.unwrap_or(()) }));

    let event = security_event();
    accept_event(store.as_ref(), &serde_json::to_vec(&event).unwrap(), 100)
        .await
        .unwrap();

    let alert = tokio::time::timeout(Duration::from_secs(10), alerts.recv())
        .await
        .expect("no dead-letter alert was published")
        .unwrap();
    stop.send(()).unwrap();
    handle.await.unwrap();

    let dead = format!("deliver:{}:security_alert:webhook", event.id);
    let dead_record = record(store.as_ref(), &dead).await.unwrap();
    assert_eq!(dead_record.state, WorkState::Failed);
    assert_eq!(dead_record.attempts, 1, "a rejected delivery was retried");
    assert_eq!(alert.data["work_id"], dead_record.id.to_string());

    let sent = format!("deliver:{}:security_alert:email", event.id);
    let sent_record = record(store.as_ref(), &sent).await.unwrap();
    assert_eq!(sent_record.state, WorkState::Completed);
    assert_eq!(sent_record.result.as_deref(), Some("smtp:email:m-42"));
    assert_eq!(email.sent.lock().unwrap().len(), 1);
}
