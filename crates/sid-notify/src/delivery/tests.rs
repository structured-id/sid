// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::recipient_resolver::RecipientResolver;
use crate::template::TemplateEngine;
use chrono::Utc;
use sid_authn::event_relay::{EventFanoutHandler, EventRelayHandler};
use sid_authn::work_runner::{RunnerConfig, WorkRunner};
use sid_core::models::RequiredReceiver;
use sid_core::models::WorkState;
use sid_core::models::event::EventFilter;
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

fn route_handler(
    store: &Arc<dyn WorkStore>,
    resolver: impl RecipientSource + 'static,
) -> RouteHandler {
    RouteHandler::new(
        RoutingTable::default_ce_rules(),
        Arc::new(resolver),
        Arc::clone(store),
        1_000,
    )
}

/// The standalone source, which keeps every routed recipient.
fn standalone() -> Arc<dyn RecipientSource> {
    Arc::new(RecipientResolver::without_identity())
}

fn owner() -> Recipient {
    Recipient {
        profile_id: "org/o-1".into(),
        email: Some("owner@sid.example.com".into()),
        phone: None,
        push_endpoint: None,
        device_token: None,
        locale: "en".into(),
    }
}

/// A host's source: answers resolution and the recheck with fixed results
/// and counts the rechecks.
struct HostSource {
    resolved: Result<Recipient, ResolveError>,
    still: Result<bool, ResolveError>,
    rechecks: Mutex<u32>,
}

impl HostSource {
    fn new(resolved: Result<Recipient, ResolveError>, still: Result<bool, ResolveError>) -> Self {
        Self {
            resolved,
            still,
            rechecks: Mutex::new(0),
        }
    }
}

#[async_trait]
impl RecipientSource for HostSource {
    async fn resolve(&self, _event: &Event) -> Result<Recipient, ResolveError> {
        self.resolved.clone()
    }

    async fn still_recipient(
        &self,
        _event: &Event,
        _recipient: &Recipient,
    ) -> Result<bool, ResolveError> {
        *self.rechecks.lock().unwrap() += 1;
        self.still.clone()
    }
}

fn delivery_to(recipient: Recipient, channel: &str) -> ClaimedWork {
    let job = DeliveryJob {
        event: security_event(),
        template: "security_alert".into(),
        priority: NotificationPriority::Critical,
        channel: channel.into(),
        recipient,
    };
    claimed(DELIVER, serde_json::to_vec(&job).unwrap())
}

/// Run every plan job `store` holds once with `handler`, returning the
/// outcomes.
async fn carry_out_plans(store: &Arc<dyn WorkStore>, handler: &PlanHandler) -> Vec<WorkOutcome> {
    let plans = store
        .claim_work(&[kind(PLAN)], "w", 10, Duration::from_secs(30))
        .await
        .unwrap();
    let mut outcomes = Vec::new();
    for plan in plans {
        let outcome = handler.handle(&plan).await;
        match &outcome {
            WorkOutcome::Done(result) => {
                store
                    .complete_work(plan.id, plan.generation, result.as_deref())
                    .await
                    .unwrap();
            }
            WorkOutcome::Retry(error) => {
                store
                    .fail_work(
                        plan.id,
                        plan.generation,
                        &sid_core::models::WorkFailure {
                            error: error.clone(),
                            ambiguous: false,
                            retry_at: Some(Utc::now()),
                            on_dead: None,
                        },
                    )
                    .await
                    .unwrap();
            }
            other => panic!("unexpected plan outcome {other:?}"),
        }
        outcomes.push(outcome);
    }
    outcomes
}

/// An accepted event is owned by one routing job, however often the bus
/// redelivers it (also after a crash between storing and settling); another
/// producer's event with the same id is a different fact with its own job.
#[tokio::test]
async fn test_accept_event_is_idempotent_per_event() {
    let store = store().await;
    let event = security_event();
    accept_event(store.as_ref(), &event, 10).await.unwrap();
    accept_event(store.as_ref(), &event, 10).await.unwrap();

    let route = store
        .get_work(route_job_id(&event))
        .await
        .unwrap()
        .expect("accepted event has no routing job");
    assert_eq!(route.state, WorkState::Pending);
    assert_eq!(route.max_attempts, MAX_ATTEMPTS);
    let claimed = store
        .claim_work(&[kind(ROUTE)], "w", 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1, "a redelivered event was stored twice");

    let mut other_source = event.clone();
    other_source.source = "sid-other".into();
    assert_ne!(route_job_id(&other_source), route_job_id(&event));
}

/// A full job store refuses the event, so the bus keeps it.
#[tokio::test]
async fn test_accept_event_refused_when_full() {
    let store = store().await;
    let (first, second) = (security_event(), security_event());
    accept_event(store.as_ref(), &first, 1).await.unwrap();
    let refused = accept_event(store.as_ref(), &second, 1).await;
    assert!(matches!(
        refused,
        Err(sid_core::Error::ResourceExhausted(_))
    ));
}

/// Routing stores one delivery per (template, channel) with a stable id; a
/// second routing attempt stores nothing new.
/// Two producers may reuse an event id: each event is its own notification,
/// so routing them stores deliveries for both rather than taking the second
/// for a repeat of the first.
#[tokio::test]
async fn test_same_id_from_two_sources_is_two_notifications() {
    let store = store().await;
    let handler = route_handler(&store, RecipientResolver::without_identity());
    let first = security_event();
    let mut second = first.clone();
    second.source = "sid-other".into();
    for event in [&first, &second] {
        let work = claimed(ROUTE, serde_json::to_vec(event).unwrap());
        assert_eq!(
            handler.handle(&work).await,
            WorkOutcome::Done(Some("2 deliveries planned".into()))
        );
    }
    carry_out_plans(&store, &PlanHandler::new(Arc::clone(&store), 1_000)).await;
    let deliveries = store
        .claim_work(&[kind(DELIVER)], "w", 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(
        deliveries.len(),
        4,
        "a second source's deliveries were dropped"
    );
}

#[tokio::test]
async fn test_route_fans_out_once() {
    let store = store().await;
    let handler = route_handler(&store, RecipientResolver::without_identity());
    let event = security_event();
    let work = claimed(ROUTE, serde_json::to_vec(&event).unwrap());

    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("2 deliveries planned".into()))
    );
    handler.handle(&work).await;
    let plans = PlanHandler::new(Arc::clone(&store), 1_000);
    assert_eq!(
        carry_out_plans(&store, &plans).await,
        [WorkOutcome::Done(Some("2 deliveries".into()))],
        "a repeated routing stored its plan twice"
    );

    for channel in ["email", "webhook"] {
        let id = delivery_job_id(&event, "security_alert", channel);
        assert!(
            store.get_work(id).await.unwrap().is_some(),
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

/// A fan-out cut short after one delivery was stored finishes the rest even
/// when the rules changed meanwhile: the plan stored by the first routing is
/// carried out whole, each delivery once. Routing once resolved the rules
/// again on every attempt, so a rule removed between attempts dropped the
/// remaining delivery while the routing reported done.
#[tokio::test]
async fn test_partial_fan_out_finishes_after_a_rule_change() {
    let store = store().await;
    let event = security_event();
    let work = claimed(ROUTE, serde_json::to_vec(&event).unwrap());
    assert!(matches!(
        route_handler(&store, RecipientResolver::without_identity())
            .handle(&work)
            .await,
        WorkOutcome::Done(_)
    ));

    // Room for one delivery only: the plan stores the first and stays owed.
    let cramped = PlanHandler::new(Arc::clone(&store), 1);
    assert!(matches!(
        carry_out_plans(&store, &cramped).await.as_slice(),
        [WorkOutcome::Retry(_)]
    ));

    // The rules change: routing the event again now matches nothing, and
    // owes nothing new.
    let silent = RouteHandler::new(RoutingTable::new(), standalone(), Arc::clone(&store), 1_000);
    assert_eq!(
        silent.handle(&work).await,
        WorkOutcome::Done(Some("no routing rule".into()))
    );

    let roomy = PlanHandler::new(Arc::clone(&store), 1_000);
    assert_eq!(
        carry_out_plans(&store, &roomy).await,
        [WorkOutcome::Done(Some("2 deliveries".into()))]
    );
    for channel in ["email", "webhook"] {
        let id = delivery_job_id(&event, "security_alert", channel);
        assert!(
            store.get_work(id).await.unwrap().is_some(),
            "the planned {channel} delivery was dropped"
        );
    }
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
    // A Profile that could exist: only asking the service can resolve it.
    let event = Event::new("sid-server", event_types::SECURITY_BRUTE_FORCE)
        .with_subject(format!("profile/{}", sid_ids::ProfileId::generate()));
    let work = claimed(ROUTE, serde_json::to_vec(&event).unwrap());
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
        delivery_to(
            Recipient {
                profile_id: "p-1".into(),
                email: Some("alice@sid.example.com".into()),
                ..owner()
            },
            channel,
        )
    };
    let email = ScriptedChannel::new("email", accepted);
    let rejected = ScriptedChannel::new("rejected", || {
        Err(DeliveryError::Rejected("550 no such user".into()))
    });
    let lost = ScriptedChannel::new("lost", || {
        Err(DeliveryError::Ambiguous("timed out after DATA".into()))
    });
    let busy = ScriptedChannel::new("busy", || Err(DeliveryError::Failed("421".into())));
    let handler = DeliverHandler::new(
        dispatcher(&[Arc::clone(&email), rejected, lost, busy]),
        standalone(),
    );

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

/// A host's source decides the recipient: the plan carries the recipient the
/// source resolved, not the address the event's data names, and a source
/// that cannot answer keeps the routing owed.
#[tokio::test]
async fn test_host_source_decides_the_recipient() {
    let (store, other) = (store().await, store().await);
    let host = route_handler(&store, HostSource::new(Ok(owner()), Ok(true)));
    let event = security_event();
    let work = claimed(ROUTE, serde_json::to_vec(&event).unwrap());
    assert!(matches!(host.handle(&work).await, WorkOutcome::Done(_)));
    carry_out_plans(&store, &PlanHandler::new(Arc::clone(&store), 1_000)).await;
    let deliveries = store
        .claim_work(&[kind(DELIVER)], "w", 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 2);
    for delivery in &deliveries {
        let job: DeliveryJob = serde_json::from_slice(&delivery.payload).unwrap();
        assert_eq!(
            (
                job.recipient.profile_id.as_str(),
                job.recipient.email.as_deref()
            ),
            ("org/o-1", Some("owner@sid.example.com")),
            "the event's own address was used"
        );
    }

    let down = route_handler(
        &other,
        HostSource::new(
            Err(ResolveError::Unavailable("lookup down".into())),
            Ok(true),
        ),
    );
    assert!(matches!(down.handle(&work).await, WorkOutcome::Retry(_)));
    assert!(
        other.get_work(plan_job_id(&event)).await.unwrap().is_none(),
        "a plan was stored without a recipient"
    );
    let gone = route_handler(
        &other,
        HostSource::new(Err(ResolveError::ProfileGone("no owner".into())), Ok(true)),
    );
    assert!(matches!(
        gone.handle(&work).await,
        WorkOutcome::Permanent(_)
    ));
}

/// Authority is rechecked before every attempt: a recipient that may no
/// longer receive the event is sent nothing and the delivery ends; a recheck
/// that cannot be answered sends nothing and keeps the delivery owed.
#[tokio::test]
async fn test_delivery_rechecks_the_recipient_before_sending() {
    let email = ScriptedChannel::new("email", accepted);
    for (still, ended) in [
        (Ok(false), true),
        (Err(ResolveError::ProfileGone("org closed".into())), true),
        (Err(ResolveError::Unavailable("lookup down".into())), false),
    ] {
        let source = Arc::new(HostSource::new(Ok(owner()), still));
        let handler = DeliverHandler::new(
            dispatcher(&[Arc::clone(&email)]),
            Arc::clone(&source) as Arc<dyn RecipientSource>,
        );
        let outcome = handler.handle(&delivery_to(owner(), "email")).await;
        if ended {
            assert!(matches!(outcome, WorkOutcome::Permanent(_)), "{outcome:?}");
        } else {
            assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");
        }
        assert_eq!(*source.rechecks.lock().unwrap(), 1);
    }
    assert!(
        email.sent.lock().unwrap().is_empty(),
        "a recipient without authority was sent the message"
    );

    let source = Arc::new(HostSource::new(Ok(owner()), Ok(true)));
    let handler = DeliverHandler::new(
        dispatcher(&[Arc::clone(&email)]),
        Arc::clone(&source) as Arc<dyn RecipientSource>,
    );
    assert!(matches!(
        handler.handle(&delivery_to(owner(), "email")).await,
        WorkOutcome::Done(_)
    ));
    assert_eq!(email.sent.lock().unwrap().len(), 1);
}

/// End to end: an accepted event is routed and delivered by the runner; a
/// delivery that fails for good ends failed, and its alert is relayed as
/// every fact is: owed to the deployment's other required receivers and
/// published to history.
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
        Arc::new(PlanHandler::new(Arc::clone(&store), 1_000)),
        Arc::new(DeliverHandler::new(
            dispatcher(&[Arc::clone(&email), webhook]),
            standalone(),
        )),
        Arc::new(EventRelayHandler::new(
            Arc::clone(&store),
            vec![RequiredReceiver {
                recipient: WorkRecipient::new("audit-sink").unwrap(),
                event_types: Vec::new(),
            }],
            100,
        )),
        Arc::new(EventFanoutHandler::new(
            bus.clone(),
            Arc::clone(&store),
            100,
        )),
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
    accept_event(store.as_ref(), &event, 100).await.unwrap();

    let alert = tokio::time::timeout(Duration::from_secs(10), alerts.recv())
        .await
        .expect("no dead-letter alert was published")
        .unwrap();
    stop.send(()).unwrap();
    handle.await.unwrap();

    let dead_record = store
        .get_work(delivery_job_id(&event, "security_alert", "webhook"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dead_record.state, WorkState::Failed);
    assert_eq!(dead_record.attempts, 1, "a rejected delivery was retried");
    assert_eq!(alert.data["work_id"], dead_record.id.to_string());
    let owed = store
        .get_work(alert.delivery_id(&WorkRecipient::new("audit-sink").unwrap()))
        .await
        .unwrap()
        .expect("the alert was not owed to the required receiver");
    assert_eq!(owed.state, WorkState::Pending);

    let sent_record = store
        .get_work(delivery_job_id(&event, "security_alert", "email"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sent_record.state, WorkState::Completed);
    assert_eq!(sent_record.result.as_deref(), Some("smtp:email:m-42"));
    assert_eq!(email.sent.lock().unwrap().len(), 1);
}
