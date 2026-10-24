use super::*;
use sid_core::models::{
    AttributeMapping, DirectoryGroupWrite, DirectoryWriteMode, Group, GroupMappingEntry,
    GroupMember, GroupPushConfig, OutboundAuthConfig, OutboundSyncConfig, Profile, ProfileStatus,
    ProjectId,
};
use sid_plugin::WorkStore;
use sid_plugin::event_bus::{InProcessEventBus, Settlement};
use sid_storage::sqlite::SqliteBackend;

use std::collections::HashMap;
use std::sync::Mutex;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde_json::{Value, json};

/// Outbound provisioning is owed the facts it pushes and nothing else: its
/// own failure facts are not delivered back to it, where every recorded
/// failure would be dispatched again to each target as a no-op.
#[test]
fn test_the_receiver_takes_only_what_it_pushes() {
    let receiver = required_receiver();
    for pushed in [
        event_types::SCIM_USER_PROVISIONED,
        event_types::SCIM_USER_UPDATED,
        event_types::SCIM_USER_DEACTIVATED,
        event_types::SCIM_USER_REACTIVATED,
        event_types::SCIM_GROUP_CREATED,
        event_types::SCIM_GROUP_UPDATED,
        event_types::SCIM_GROUP_DELETED,
    ] {
        assert!(receiver.requires(pushed), "{pushed} not owed");
    }
    assert!(
        !receiver.requires(event_types::SCIM_OUTBOUND_FAILED),
        "its own failure fact is owed back to it"
    );
}

#[test]
fn test_extract_profile_id_valid() {
    let uuid = Uuid::now_v7();
    let data = serde_json::json!({"profile_id": uuid.to_string()});
    let result = extract_profile_id(&data);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().into_uuid(), uuid);
}

#[test]
fn test_extract_profile_id_missing() {
    let data = serde_json::json!({"other": "value"});
    let result = extract_profile_id(&data);
    assert!(result.is_err());
}

#[test]
fn test_extract_profile_id_invalid() {
    let data = serde_json::json!({"profile_id": "not-a-uuid"});
    let result = extract_profile_id(&data);
    assert!(result.is_err());
}

#[test]
fn test_extract_uuid_field() {
    let uuid = Uuid::now_v7();
    let data = serde_json::json!({"group_id": uuid.to_string()});
    let result = extract_uuid_field(&data, "group_id");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), uuid);
}

#[test]
fn test_extract_uuid_field_missing() {
    let data = serde_json::json!({});
    let result = extract_uuid_field(&data, "group_id");
    assert!(result.is_err());
}

#[test]
fn test_error_class_classification() {
    assert_eq!(
        error_class(&ScimClientError::Unreachable("timeout".into())),
        "unreachable"
    );
    assert_eq!(
        error_class(&ScimClientError::Rejected {
            status: 400,
            body: "bad request".into()
        }),
        "rejected"
    );
    assert_eq!(
        error_class(&ScimClientError::RateLimited {
            retry_after_secs: 30
        }),
        "rate_limited"
    );
    assert_eq!(
        error_class(&ScimClientError::Conflict {
            body: "conflict".into()
        }),
        "conflict"
    );
    assert_eq!(
        error_class(&ScimClientError::AuthFailed { status: 401 }),
        "auth_failed"
    );
    assert_eq!(
        error_class(&ScimClientError::Serialization("bad json".into())),
        "serialization"
    );
    assert_eq!(error_class(&ScimClientError::NotHeld), "not_held");
}

/// The pause before a failed dispatch is tried again: the target's
/// Retry-After, or its base doubling per attempt, never past the ceiling.
#[test]
fn test_backoff() {
    let t = target("a", true, "http://127.0.0.1:1/scim/v2");
    let down = ScimClientError::Unreachable("down".into());
    assert_eq!(backoff(&down, 1, &t), Duration::from_secs(1));
    assert_eq!(backoff(&down, 3, &t), Duration::from_secs(4));
    assert_eq!(backoff(&down, 200, &t), MAX_BACKOFF);
    let limited = ScimClientError::RateLimited {
        retry_after_secs: 7,
    };
    assert_eq!(backoff(&limited, 1, &t), Duration::from_secs(7));
    assert_eq!(backoff(&ScimClientError::NotHeld, 9, &t), NOT_HELD_RETRY);
}

fn target(name: &str, enabled: bool, endpoint: &str) -> ScimOutboundTarget {
    ScimOutboundTarget {
        id: ScimOutboundTargetId::new(),
        client_id: format!("{name}-app"),
        project_id: ProjectId::system(),
        display_name: name.into(),
        endpoint_url: endpoint.into(),
        auth: OutboundAuthConfig::Bearer {
            token_secret: "test-token".into(),
        },
        attribute_mapping: AttributeMapping::default(),
        group_push: GroupPushConfig {
            enabled: true,
            mapping: vec![GroupMappingEntry {
                sid_group: "Engineering".into(),
                target_group: "engineering".into(),
            }],
        },
        sync_config: OutboundSyncConfig {
            max_retry_attempts: 3,
            retry_backoff_base_secs: 1,
        },
        enabled,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// A target where nothing listens: a request to it fails at once.
fn unreachable_target(name: &str, enabled: bool) -> ScimOutboundTarget {
    target(name, enabled, "http://127.0.0.1:1/scim/v2")
}

/// A worker over `targets`, each stored as configured.
async fn worker(targets: Vec<ScimOutboundTarget>) -> (Arc<SqliteBackend>, ScimOutboundWorker) {
    crate::test_crypto::install_tls();
    let storage = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    for target in &targets {
        storage
            .create_scim_outbound_target(target, AuditEntry::system("test", "target").into())
            .await
            .unwrap();
    }
    let worker =
        ScimOutboundWorker::new(storage.clone(), Arc::new(InProcessEventBus::new()), targets);
    (storage, worker)
}

/// The first delivery of `event`, held until settled.
async fn first(worker: &ScimOutboundWorker, event: &Event) -> Settlement {
    worker.process(event, 1, &Hold::unbounded()).await
}

/// A provisioning event whose profile does not exist: every dispatch of it
/// fails for good, before any request.
fn undeliverable() -> Event {
    Event::new("sid-scim", event_types::SCIM_USER_PROVISIONED)
        .with_data(json!({"profile_id": Uuid::now_v7().to_string()}))
}

async fn dead_letters(storage: &SqliteBackend, target: &ScimOutboundTarget) -> usize {
    storage
        .list_outbound_dlq_entries(target.id)
        .await
        .unwrap()
        .len()
}

/// Every enabled target gets the event and its failure is recorded once,
/// with one alert; a disabled target gets nothing. The event redelivered
/// (its settlement lost) records no second dead letter or alert: the
/// failure and the target's outcome commit together.
#[tokio::test]
async fn test_a_redelivered_event_records_each_failure_once() {
    let (a, b, off) = (
        unreachable_target("a", true),
        unreachable_target("b", true),
        unreachable_target("off", false),
    );
    let (storage, worker) = worker(vec![a.clone(), b.clone(), off.clone()]).await;
    let event = undeliverable();

    for _ in 0..2 {
        assert_eq!(first(&worker, &event).await, Settlement::Done);
    }
    assert_eq!(
        dead_letters(&storage, &a).await,
        1,
        "a failure recorded twice"
    );
    assert_eq!(
        dead_letters(&storage, &b).await,
        1,
        "a failure recorded twice"
    );
    assert_eq!(
        dead_letters(&storage, &off).await,
        0,
        "a disabled target got it"
    );
    let alerts = storage.export_work().await.unwrap();
    assert_eq!(alerts.len(), 2, "one alert per failure, not per attempt");
}

/// A target whose outcome is recorded (it took the event before a crash) is
/// not dispatched to again when the event is redelivered; the others are.
#[tokio::test]
async fn test_a_target_with_an_outcome_is_not_dispatched_again() {
    let (a, b) = (unreachable_target("a", true), unreachable_target("b", true));
    let (storage, worker) = worker(vec![a.clone(), b.clone()]).await;
    let event = undeliverable();
    assert!(worker.record_taken(&a, &event).await);

    assert_eq!(first(&worker, &event).await, Settlement::Done);
    assert_eq!(dead_letters(&storage, &a).await, 0, "a took it twice");
    assert_eq!(dead_letters(&storage, &b).await, 1);
}

/// A target whose failure cannot be recorded leaves the event with the bus,
/// to come again; on its redelivery the target whose failure was recorded
/// is not dispatched to again.
#[tokio::test]
async fn test_an_unrecorded_failure_retries_only_its_target() {
    let a = unreachable_target("a", true);
    // Not stored: its dead letter cannot be written.
    let ghost = unreachable_target("ghost", true);
    let (storage, _) = worker(vec![a.clone()]).await;
    let worker = ScimOutboundWorker::new(
        storage.clone(),
        Arc::new(InProcessEventBus::new()),
        vec![a.clone(), ghost],
    );
    let event = undeliverable();

    for _ in 0..2 {
        assert_eq!(
            first(&worker, &event).await,
            Settlement::Retry(UNRECORDED_RETRY)
        );
    }
    assert_eq!(
        dead_letters(&storage, &a).await,
        1,
        "a failure recorded twice"
    );
}

/// A host that selected no TLS backend has no client to deliver with: that is
/// no failure of the target. The event stays with the bus for every target,
/// none of their attempts are used up and nothing reaches a dead-letter store,
/// although the same event fails for good once a client exists.
#[tokio::test]
async fn test_a_missing_tls_selection_spends_no_target_attempts() {
    let a = unreachable_target("a", true);
    // Built without the test host's selection, unlike `worker`.
    let storage = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    storage
        .create_scim_outbound_target(&a, AuditEntry::system("test", "target").into())
        .await
        .unwrap();
    let worker = ScimOutboundWorker::new(
        storage.clone(),
        Arc::new(InProcessEventBus::new()),
        vec![a.clone()],
    );
    let event = undeliverable();

    for attempt in 1..=u64::from(a.sync_config.max_retry_attempts) + 2 {
        assert_eq!(
            worker.process(&event, attempt, &Hold::unbounded()).await,
            Settlement::Retry(UNRECORDED_RETRY),
            "attempt {attempt}"
        );
    }
    assert_eq!(dead_letters(&storage, &a).await, 0, "moved to the DLQ");
}

/// A failure of SID's own storage is no failure of the target: the event is
/// retried, the target's attempts are not used up and nothing goes to its
/// dead-letter store, however many deliveries the storage keeps failing.
#[tokio::test]
async fn test_a_storage_failure_spends_no_target_attempts() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    // The mappings cannot be read; the attempt counter and dead letters can.
    sqlx::query("DROP TABLE scim_outbound_records")
        .execute(storage.pool())
        .await
        .unwrap();
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);

    for attempt in 1..=u64::from(t.sync_config.max_retry_attempts) + 2 {
        assert!(
            matches!(
                worker
                    .process(&provisioned, attempt, &Hold::unbounded())
                    .await,
                Settlement::Retry(_)
            ),
            "attempt {attempt} settled"
        );
    }
    assert_eq!(dead_letters(&storage, &t).await, 0, "moved to the DLQ");
    assert_eq!(down.lock().unwrap().requests, 0);
}

// ── A stand-in downstream SCIM server ──

/// What the stand-in target holds and how it misbehaves.
#[derive(Default)]
struct Downstream {
    users: Vec<Value>,
    groups: Vec<Value>,
    /// Requests received.
    requests: usize,
    /// Store the next create, then answer 500: its response is lost.
    lose_next_create: bool,
    /// Answer the next lookup 200 with this body instead of a list.
    garble_next_find: Option<&'static str>,
    /// Creates received.
    creates: usize,
    /// Answer every request with this status, changing nothing.
    fail_with: Option<u16>,
    /// Answer the next modification with this status, changing nothing.
    fail_next_modify: Option<u16>,
}

type Shared = Arc<Mutex<Downstream>>;

impl Downstream {
    fn resources(&mut self, kind: &str) -> &mut Vec<Value> {
        match kind {
            "Users" => &mut self.users,
            "Groups" => &mut self.groups,
            other => panic!("no {other} resources"),
        }
    }
}

/// The attribute a resource of `kind` is unique by (RFC 7643 §4.1.1, §4.2).
fn unique_by(kind: &str) -> &'static str {
    if kind == "Users" {
        "userName"
    } else {
        "displayName"
    }
}

/// Start the stand-in target: its SCIM base URL and its state.
async fn downstream() -> (String, Shared) {
    async fn admit(state: &Shared) -> Result<(), StatusCode> {
        let mut d = state.lock().unwrap();
        d.requests += 1;
        match d.fail_with {
            Some(status) => Err(StatusCode::from_u16(status).unwrap()),
            None => Ok(()),
        }
    }
    async fn create(
        State(state): State<Shared>,
        Path(kind): Path<String>,
        Json(mut body): Json<Value>,
    ) -> Result<(StatusCode, Json<Value>), StatusCode> {
        admit(&state).await?;
        let mut d = state.lock().unwrap();
        d.creates += 1;
        let key = unique_by(&kind);
        if d.resources(&kind).iter().any(|r| r[key] == body[key]) {
            return Err(StatusCode::CONFLICT);
        }
        body["id"] = json!(Uuid::now_v7().to_string());
        d.resources(&kind).push(body.clone());
        if std::mem::take(&mut d.lose_next_create) {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok((StatusCode::CREATED, Json(body)))
    }
    async fn find(
        State(state): State<Shared>,
        Path(kind): Path<String>,
        Query(query): Query<HashMap<String, String>>,
    ) -> Result<String, StatusCode> {
        admit(&state).await?;
        let filter = query.get("filter").ok_or(StatusCode::BAD_REQUEST)?;
        let (attribute, literal) = filter.split_once(" eq ").ok_or(StatusCode::BAD_REQUEST)?;
        let wanted: String = serde_json::from_str(literal).map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut d = state.lock().unwrap();
        if let Some(garbled) = d.garble_next_find.take() {
            return Ok(garbled.to_string());
        }
        let found: Vec<Value> = d
            .resources(&kind)
            .iter()
            .filter(|r| r[attribute] == json!(wanted))
            .cloned()
            .collect();
        Ok(json!({"totalResults": found.len(), "Resources": found}).to_string())
    }
    async fn modify(
        State(state): State<Shared>,
        Path((kind, id)): Path<(String, String)>,
        Json(body): Json<Value>,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        let invalid = |scim_type: &str| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "400", "scimType": scim_type})),
            )
        };
        admit(&state).await.map_err(|s| (s, Json(json!({}))))?;
        let mut d = state.lock().unwrap();
        if let Some(status) = d.fail_next_modify.take() {
            return Err((StatusCode::from_u16(status).unwrap(), Json(json!({}))));
        }
        let resource = d
            .resources(&kind)
            .iter_mut()
            .find(|r| r["id"] == json!(id))
            .ok_or((StatusCode::NOT_FOUND, Json(json!({}))))?;
        // Atomic (RFC 7644 §3.5.2): every operation applies, or none does.
        let mut patched = resource.clone();
        for op in body["Operations"]
            .as_array()
            .ok_or_else(|| invalid("invalidSyntax"))?
        {
            let path = op["path"].as_str().ok_or_else(|| invalid("invalidPath"))?;
            match op["op"].as_str() {
                Some("replace") => patched[path] = op["value"].clone(),
                // A strict provider: removing what is not there is noTarget
                // (RFC 7644 §3.5.2.2).
                Some("remove") => {
                    if patched.as_object_mut().unwrap().remove(path).is_none() {
                        return Err(invalid("noTarget"));
                    }
                }
                _ => return Err(invalid("invalidSyntax")),
            }
        }
        *resource = patched;
        Ok(Json(resource.clone()))
    }
    async fn delete(
        State(state): State<Shared>,
        Path((kind, id)): Path<(String, String)>,
    ) -> StatusCode {
        if let Err(status) = admit(&state).await {
            return status;
        }
        let mut d = state.lock().unwrap();
        let resources = d.resources(&kind);
        let before = resources.len();
        resources.retain(|r| r["id"] != json!(id));
        if resources.len() < before {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    }

    let state = Shared::default();
    let app = Router::new()
        .route("/scim/v2/{kind}", get(find).post(create))
        .route("/scim/v2/{kind}/{id}", patch(modify).delete(delete))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}/scim/v2"), state)
}

/// A stored active profile named `name`.
async fn stored_profile(storage: &SqliteBackend, name: &str) -> Profile {
    let mut profile = Profile::new(Some(name));
    profile.status = ProfileStatus::Active;
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    storage.get_profile(profile.id).await.unwrap().unwrap()
}

/// Set the stored profile's status.
async fn set_status(storage: &SqliteBackend, profile: ProfileId, status: ProfileStatus) {
    let mut stored = storage.get_profile(profile).await.unwrap().unwrap();
    stored.status = status;
    assert!(
        storage
            .update_profile(&stored, AuditEntry::system("test", "status").into())
            .await
            .unwrap()
    );
}

fn user_event(event_type: &str, profile: ProfileId) -> Event {
    Event::new("sid-scim", event_type).with_data(json!({"profile_id": profile.to_string()}))
}

fn group_event(event_type: &str, group: GroupId) -> Event {
    Event::new("sid-scim", event_type).with_data(json!({"group_id": group.0.to_string()}))
}

/// A deactivation delivered after the reactivation that followed it (a
/// late or reordered delivery) does not roll the downstream user back to
/// inactive: every push carries the profile's current state.
#[tokio::test]
async fn test_a_late_deactivation_does_not_roll_back_the_user() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t]).await;
    let alice = stored_profile(&storage, "alice").await;
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert_eq!(first(&worker, &provisioned).await, Settlement::Done);

    set_status(&storage, alice.id, ProfileStatus::Suspended).await;
    let deactivated = user_event(event_types::SCIM_USER_DEACTIVATED, alice.id);
    set_status(&storage, alice.id, ProfileStatus::Active).await;
    let reactivated = user_event(event_types::SCIM_USER_REACTIVATED, alice.id);

    assert_eq!(first(&worker, &reactivated).await, Settlement::Done);
    assert_eq!(first(&worker, &deactivated).await, Settlement::Done);
    let d = down.lock().unwrap();
    assert_eq!(d.users.len(), 1);
    assert_eq!(
        d.users[0]["active"],
        json!(true),
        "a stale event restored an older state"
    );
}

/// An update the relay published before the provisioning it followed (the
/// stages before the bus run concurrently) creates the user once: the
/// update pushes the current state, and the late provisioning finds the user
/// mapped and replaces it rather than creating another.
#[tokio::test]
async fn test_an_update_before_its_provisioning_creates_the_user_once() {
    let (endpoint, down) = downstream().await;
    let (storage, worker) = worker(vec![target("app", true, &endpoint)]).await;
    let alice = stored_profile(&storage, "alice").await;
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    let updated = user_event(event_types::SCIM_USER_UPDATED, alice.id);

    assert_eq!(first(&worker, &updated).await, Settlement::Done);
    assert_eq!(first(&worker, &provisioned).await, Settlement::Done);
    assert_eq!(down.lock().unwrap().users.len(), 1, "created twice");
}

/// A create whose response was lost (the target stored it, the answer never
/// arrived) is not created a second time: the next attempt finds it by
/// userName and pushes the state to it.
#[tokio::test]
async fn test_a_lost_create_response_creates_the_user_once() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    down.lock().unwrap().lose_next_create = true;
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);

    assert!(matches!(
        first(&worker, &provisioned).await,
        Settlement::Retry(_)
    ));
    assert_eq!(
        worker.process(&provisioned, 2, &Hold::unbounded()).await,
        Settlement::Done
    );
    assert_eq!(down.lock().unwrap().users.len(), 1, "created twice");
    assert_eq!(dead_letters(&storage, &t).await, 0);
    let mapped = storage
        .get_scim_outbound_record(t.id, alice.id.into_uuid(), OutboundEntityType::User)
        .await
        .unwrap()
        .expect("the found user is mapped");
    assert_eq!(
        json!(mapped.downstream_id),
        down.lock().unwrap().users[0]["id"]
    );
}

/// A user renamed after a create whose response was lost is found under the
/// name the create was sent with, not created again under the new one, and
/// then takes the new name.
#[tokio::test]
async fn test_a_user_renamed_after_a_lost_create_is_created_once() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    down.lock().unwrap().lose_next_create = true;
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert!(matches!(
        first(&worker, &provisioned).await,
        Settlement::Retry(_)
    ));

    let mut renamed = storage.get_profile(alice.id).await.unwrap().unwrap();
    renamed.username = Some("alicia".into());
    assert!(
        storage
            .update_profile(&renamed, AuditEntry::system("test", "rename").into())
            .await
            .unwrap()
    );
    assert_eq!(
        worker.process(&provisioned, 2, &Hold::unbounded()).await,
        Settlement::Done
    );
    let d = down.lock().unwrap();
    assert_eq!(d.users.len(), 1, "created again under the new name");
    assert_eq!(d.users[0]["userName"], json!("alicia"));
}

/// The same for a group: renamed after its create's response was lost, it
/// is found under the downstream name it was created with and given the one
/// its new name maps to, once.
#[tokio::test]
async fn test_a_group_renamed_after_a_lost_create_is_created_once() {
    let (endpoint, down) = downstream().await;
    let mut t = target("app", true, &endpoint);
    t.group_push.mapping.push(GroupMappingEntry {
        sid_group: "Platform".into(),
        target_group: "platform".into(),
    });
    let (storage, worker) = worker(vec![t.clone()]).await;
    let group = Group::new(ProjectId::system(), "Engineering");
    storage
        .write_directory_group(
            &DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone()),
            AuditEntry::system("test", "group").into(),
        )
        .await
        .unwrap();
    down.lock().unwrap().lose_next_create = true;
    let created = group_event(event_types::SCIM_GROUP_CREATED, group.id);
    assert!(matches!(
        first(&worker, &created).await,
        Settlement::Retry(_)
    ));

    let mut renamed = group.clone();
    renamed.name = "Platform".into();
    storage
        .write_directory_group(
            &DirectoryGroupWrite::new(DirectoryWriteMode::Update, renamed),
            AuditEntry::system("test", "rename").into(),
        )
        .await
        .unwrap();
    assert_eq!(
        worker.process(&created, 2, &Hold::unbounded()).await,
        Settlement::Done
    );
    let d = down.lock().unwrap();
    assert_eq!(d.groups.len(), 1, "created again under the new name");
    assert_eq!(d.groups[0]["displayName"], json!("platform"));
}

/// After a lost create response, a lookup answered with something that is
/// not a readable list (not JSON, no `Resources`, a match without `id`)
/// proves nothing about the user: the attempt is retried, never turned into
/// a second create, and the next readable lookup finds the user.
#[tokio::test]
async fn test_an_unreadable_lookup_after_a_lost_create_creates_nothing() {
    for garbled in [
        "not json",
        "{}",
        r#"{"totalResults": 1, "Resources": "alice"}"#,
        r#"{"totalResults": 1, "Resources": [{"userName": "alice"}]}"#,
    ] {
        let (endpoint, down) = downstream().await;
        let t = target("app", true, &endpoint);
        let (storage, worker) = worker(vec![t.clone()]).await;
        let alice = stored_profile(&storage, "alice").await;
        down.lock().unwrap().lose_next_create = true;
        let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
        assert!(matches!(
            first(&worker, &provisioned).await,
            Settlement::Retry(_)
        ));

        down.lock().unwrap().garble_next_find = Some(garbled);
        assert!(
            matches!(
                worker.process(&provisioned, 2, &Hold::unbounded()).await,
                Settlement::Retry(_)
            ),
            "{garbled}: not retried"
        );
        assert_eq!(down.lock().unwrap().creates, 1, "{garbled}: created again");
        assert_eq!(
            worker.process(&provisioned, 3, &Hold::unbounded()).await,
            Settlement::Done,
            "{garbled}"
        );
        assert_eq!(down.lock().unwrap().creates, 1, "{garbled}: created again");
        assert_eq!(dead_letters(&storage, &t).await, 0, "{garbled}");
    }
}

/// A create recorded as sent but that never reached the target (refused,
/// or the process stopped before sending) is sent again: the lookup finding
/// nothing lets the next attempt create the user.
#[tokio::test]
async fn test_a_create_that_never_landed_is_sent_again() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    down.lock().unwrap().fail_with = Some(503);
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);

    assert!(matches!(
        first(&worker, &provisioned).await,
        Settlement::Retry(_)
    ));
    assert!(down.lock().unwrap().users.is_empty());
    down.lock().unwrap().fail_with = None;
    assert_eq!(
        worker.process(&provisioned, 2, &Hold::unbounded()).await,
        Settlement::Done
    );
    assert_eq!(down.lock().unwrap().users.len(), 1, "never created");
    assert_eq!(dead_letters(&storage, &t).await, 0);
}

/// An inactive user the target never had is not created.
#[tokio::test]
async fn test_an_inactive_user_is_not_created() {
    let (endpoint, down) = downstream().await;
    let (storage, worker) = worker(vec![target("app", true, &endpoint)]).await;
    let alice = stored_profile(&storage, "alice").await;
    set_status(&storage, alice.id, ProfileStatus::Suspended).await;
    let deactivated = user_event(event_types::SCIM_USER_DEACTIVATED, alice.id);
    assert_eq!(first(&worker, &deactivated).await, Settlement::Done);
    assert!(down.lock().unwrap().users.is_empty());
}

/// A group is pushed with its current membership whichever of its events
/// comes, and late events after a member left do not bring it back; once
/// deleted, its downstream copy is deleted.
#[tokio::test]
async fn test_a_group_follows_its_current_membership() {
    let (endpoint, down) = downstream().await;
    let (storage, worker) = worker(vec![target("app", true, &endpoint)]).await;
    let (alice, bob) = (
        stored_profile(&storage, "alice").await,
        stored_profile(&storage, "bob").await,
    );
    for p in [&alice, &bob] {
        let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, p.id);
        assert_eq!(first(&worker, &provisioned).await, Settlement::Done);
    }
    let group = Group::new(ProjectId::system(), "Engineering");
    let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone());
    write.add_members.push(GroupMember::new(group.id, alice.id));
    write.add_members.push(GroupMember::new(group.id, bob.id));
    storage
        .write_directory_group(&write, AuditEntry::system("test", "group").into())
        .await
        .unwrap();
    let created = group_event(event_types::SCIM_GROUP_CREATED, group.id);

    let mut leave = DirectoryGroupWrite::new(DirectoryWriteMode::Update, group.clone());
    leave.remove_members.push(bob.id);
    storage
        .write_directory_group(&leave, AuditEntry::system("test", "leave").into())
        .await
        .unwrap();
    let updated = group_event(event_types::SCIM_GROUP_UPDATED, group.id);

    // The update first, then the late create that named both members.
    assert_eq!(first(&worker, &updated).await, Settlement::Done);
    assert_eq!(first(&worker, &created).await, Settlement::Done);
    {
        let d = down.lock().unwrap();
        assert_eq!(d.groups.len(), 1, "the group was created twice");
        let alice_id = d
            .users
            .iter()
            .find(|u| u["userName"] == json!("alice"))
            .unwrap()["id"]
            .clone();
        assert_eq!(
            d.groups[0]["members"],
            json!([{"value": alice_id}]),
            "a member who left came back"
        );
    }

    storage
        .delete_group(group.id, AuditEntry::system("test", "delete").into())
        .await
        .unwrap();
    let deleted = group_event(event_types::SCIM_GROUP_DELETED, group.id);
    for _ in 0..2 {
        assert_eq!(first(&worker, &deleted).await, Settlement::Done);
    }
    assert!(down.lock().unwrap().groups.is_empty());
}

/// An attribute the user no longer has is removed downstream, not left at
/// its old value: the push carries the whole current state. Pushing again,
/// when the target has nothing left to remove, still succeeds.
#[tokio::test]
async fn test_attributes_the_user_lost_are_removed_downstream() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let mut alice = stored_profile(&storage, "alice").await;
    alice.given_name = Some("Alice".into());
    alice.family_name = Some("Smith".into());
    assert!(
        storage
            .update_profile(&alice, AuditEntry::system("test", "name").into())
            .await
            .unwrap()
    );
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert_eq!(first(&worker, &provisioned).await, Settlement::Done);
    assert!(down.lock().unwrap().users[0].get("name").is_some());

    let mut alice = storage.get_profile(alice.id).await.unwrap().unwrap();
    alice.given_name = None;
    alice.family_name = None;
    assert!(
        storage
            .update_profile(&alice, AuditEntry::system("test", "unname").into())
            .await
            .unwrap()
    );
    let updated = user_event(event_types::SCIM_USER_UPDATED, alice.id);
    for _ in 0..2 {
        assert_eq!(first(&worker, &updated).await, Settlement::Done);
        {
            let d = down.lock().unwrap();
            assert!(d.users[0].get("name").is_none(), "{}", d.users[0]);
            assert!(d.users[0].get("displayName").is_none(), "{}", d.users[0]);
        }
    }
    assert_eq!(dead_letters(&storage, &t).await, 0);
}

/// A member whose user the target did not have yet when the group was
/// pushed (the group's event came first) joins the downstream group once
/// the user is created: creating a user pushes the groups it is in.
#[tokio::test]
async fn test_a_member_created_after_its_group_joins_it() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    let group = Group::new(ProjectId::system(), "Engineering");
    let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone());
    write.add_members.push(GroupMember::new(group.id, alice.id));
    storage
        .write_directory_group(&write, AuditEntry::system("test", "group").into())
        .await
        .unwrap();

    let created = group_event(event_types::SCIM_GROUP_CREATED, group.id);
    assert_eq!(first(&worker, &created).await, Settlement::Done);
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert_eq!(first(&worker, &provisioned).await, Settlement::Done);

    let d = down.lock().unwrap();
    let alice_id = d.users[0]["id"].clone();
    assert_eq!(
        d.groups[0]["members"],
        json!([{"value": alice_id}]),
        "the member never joined the downstream group"
    );
}

/// A bus recording the durable consumers opened on it.
#[derive(Default)]
struct RecordingBus {
    consumers: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl EventBus for RecordingBus {
    async fn publish(&self, _: Event) -> sid_plugin::event_bus::EventBusResult<()> {
        Ok(())
    }

    async fn subscribe(
        &self,
        _: sid_core::models::EventFilter,
    ) -> sid_plugin::event_bus::EventBusResult<mpsc::Receiver<Event>> {
        Ok(mpsc::channel(1).1)
    }

    async fn consume(
        &self,
        consumer: DurableConsumer,
    ) -> sid_plugin::event_bus::EventBusResult<mpsc::Receiver<Delivery>> {
        self.consumers
            .lock()
            .unwrap()
            .push(consumer.recipient.to_string());
        Ok(mpsc::channel(1).1)
    }

    async fn health_check(&self) -> sid_plugin::event_bus::EventBusResult<()> {
        Ok(())
    }
}

/// Without targets (the last one removed) the worker still consumes its
/// work, so deliveries owed while targets were configured are settled
/// rather than left in the work stream; no new fact is owed to it.
#[tokio::test]
async fn test_work_owed_before_the_last_target_was_removed_is_consumed() {
    let (storage, idle) = worker(Vec::new()).await;
    let bus = Arc::new(RecordingBus::default());
    let owed = Arc::new(ScimOutboundWorker::new(
        storage.clone(),
        bus.clone(),
        Vec::new(),
    ))
    .start_owed()
    .await
    .unwrap();
    assert!(owed.is_none(), "facts are owed to a worker without targets");
    assert_eq!(
        *bus.consumers.lock().unwrap(),
        [SCIM_OUTBOUND_RECEIVER],
        "the owed work is not consumed"
    );

    // With no target to push to, a delivery is settled.
    let alice = stored_profile(&storage, "alice").await;
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert_eq!(first(&idle, &provisioned).await, Settlement::Done);
}

/// A bus that keeps no work (a single-binary deployment) cannot hold any
/// owed to the worker: without targets it starts without consuming.
#[tokio::test]
async fn test_a_worker_without_targets_starts_on_a_bus_that_keeps_no_work() {
    let (storage, _) = worker(Vec::new()).await;
    let owed = Arc::new(ScimOutboundWorker::new(
        storage,
        Arc::new(InProcessEventBus::new()),
        Vec::new(),
    ))
    .start_owed()
    .await
    .unwrap();
    assert!(owed.is_none());
}

/// With targets, facts are owed to the worker.
#[tokio::test]
async fn test_facts_are_owed_to_a_worker_with_targets() {
    let (storage, _) = worker(Vec::new()).await;
    let bus = Arc::new(RecordingBus::default());
    let target = target("app", true, "http://127.0.0.1:9/scim/v2");
    let owed = Arc::new(ScimOutboundWorker::new(storage, bus.clone(), vec![target]))
        .start_owed()
        .await
        .unwrap();
    assert!(owed.is_some());
    assert_eq!(*bus.consumers.lock().unwrap(), [SCIM_OUTBOUND_RECEIVER]);
}

/// A stored group named Engineering with `member`, pushed to the target
/// before the member's user exists there.
async fn group_pushed_before(
    worker: &ScimOutboundWorker,
    storage: &SqliteBackend,
    member: ProfileId,
) {
    let group = Group::new(ProjectId::system(), "Engineering");
    let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone());
    write.add_members.push(GroupMember::new(group.id, member));
    storage
        .write_directory_group(&write, AuditEntry::system("test", "group").into())
        .await
        .unwrap();
    let created = group_event(event_types::SCIM_GROUP_CREATED, group.id);
    assert_eq!(first(worker, &created).await, Settlement::Done);
}

/// The downstream group's members are exactly the user named `name`.
fn assert_sole_member(down: &Shared, name: &str) {
    let d = down.lock().unwrap();
    let user = d
        .users
        .iter()
        .find(|u| u["userName"] == json!(name))
        .unwrap();
    assert_eq!(
        d.groups[0]["members"],
        json!([{"value": user["id"]}]),
        "the member never joined the downstream group"
    );
}

/// A user whose create response was lost is found and mapped by the next
/// attempt, which also brings it into the groups pushed without it.
#[tokio::test]
async fn test_a_member_adopted_after_a_lost_create_joins_its_group() {
    let (endpoint, down) = downstream().await;
    let (storage, worker) = worker(vec![target("app", true, &endpoint)]).await;
    let alice = stored_profile(&storage, "alice").await;
    group_pushed_before(&worker, &storage, alice.id).await;

    down.lock().unwrap().lose_next_create = true;
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert!(matches!(
        first(&worker, &provisioned).await,
        Settlement::Retry(_)
    ));
    assert_eq!(
        worker.process(&provisioned, 2, &Hold::unbounded()).await,
        Settlement::Done
    );
    assert_sole_member(&down, "alice");
}

/// Pushing a new member's groups that fails after the user is mapped is
/// resumed by the next attempt, which finds the user already mapped.
#[tokio::test]
async fn test_a_failed_push_of_a_new_members_groups_is_resumed() {
    let (endpoint, down) = downstream().await;
    let (storage, worker) = worker(vec![target("app", true, &endpoint)]).await;
    let alice = stored_profile(&storage, "alice").await;
    group_pushed_before(&worker, &storage, alice.id).await;

    down.lock().unwrap().fail_next_modify = Some(503);
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert!(matches!(
        first(&worker, &provisioned).await,
        Settlement::Retry(_)
    ));
    assert_eq!(
        worker.process(&provisioned, 2, &Hold::unbounded()).await,
        Settlement::Done
    );
    assert_sole_member(&down, "alice");
}

/// A group the mapping lists is pushed under its configured downstream name,
/// on create and on every later push: a membership update does not rename
/// it to the SID name.
#[tokio::test]
async fn test_a_mapped_group_keeps_its_downstream_name() {
    let (endpoint, down) = downstream().await;
    let (storage, worker) = worker(vec![target("app", true, &endpoint)]).await;
    let alice = stored_profile(&storage, "alice").await;
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert_eq!(first(&worker, &provisioned).await, Settlement::Done);
    let group = Group::new(ProjectId::system(), "Engineering");
    storage
        .write_directory_group(
            &DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone()),
            AuditEntry::system("test", "group").into(),
        )
        .await
        .unwrap();
    let created = group_event(event_types::SCIM_GROUP_CREATED, group.id);
    assert_eq!(first(&worker, &created).await, Settlement::Done);
    assert_eq!(
        down.lock().unwrap().groups[0]["displayName"],
        json!("engineering")
    );

    let mut join = DirectoryGroupWrite::new(DirectoryWriteMode::Update, group.clone());
    join.add_members.push(GroupMember::new(group.id, alice.id));
    storage
        .write_directory_group(&join, AuditEntry::system("test", "join").into())
        .await
        .unwrap();
    let updated = group_event(event_types::SCIM_GROUP_UPDATED, group.id);
    assert_eq!(first(&worker, &updated).await, Settlement::Done);
    let d = down.lock().unwrap();
    assert_eq!(d.groups.len(), 1);
    assert_eq!(d.groups[0]["displayName"], json!("engineering"));
}

/// A group without members, pushed again with a new name, gets the name
/// even from a provider that refuses to remove an attribute it does not
/// have: the rename is not lost with a membership removal that had nothing
/// to remove.
#[tokio::test]
async fn test_an_empty_group_is_renamed() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let group = Group::new(ProjectId::system(), "Engineering");
    storage
        .write_directory_group(
            &DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone()),
            AuditEntry::system("test", "group").into(),
        )
        .await
        .unwrap();
    let created = group_event(event_types::SCIM_GROUP_CREATED, group.id);
    assert_eq!(first(&worker, &created).await, Settlement::Done);

    let mut renamed = group.clone();
    renamed.name = "Platform".into();
    storage
        .write_directory_group(
            &DirectoryGroupWrite::new(DirectoryWriteMode::Update, renamed),
            AuditEntry::system("test", "rename").into(),
        )
        .await
        .unwrap();
    let updated = group_event(event_types::SCIM_GROUP_UPDATED, group.id);
    for _ in 0..2 {
        assert_eq!(first(&worker, &updated).await, Settlement::Done);
    }
    {
        let d = down.lock().unwrap();
        assert_eq!(d.groups.len(), 1);
        assert_eq!(d.groups[0]["displayName"], json!("Platform"));
        assert!(d.groups[0].get("members").is_none());
    }
    assert_eq!(dead_letters(&storage, &t).await, 0);
}

/// A pushed group renamed to a name the mapping does not list is still the
/// group the target has: the rename and the members removed with it reach
/// the target (`PUT /Groups/{id}`), they are not skipped.
#[tokio::test]
async fn test_a_renamed_pushed_group_keeps_following_its_state() {
    let (endpoint, down) = downstream().await;
    let (storage, worker) = worker(vec![target("app", true, &endpoint)]).await;
    let (alice, bob) = (
        stored_profile(&storage, "alice").await,
        stored_profile(&storage, "bob").await,
    );
    for p in [&alice, &bob] {
        let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, p.id);
        assert_eq!(first(&worker, &provisioned).await, Settlement::Done);
    }
    let group = Group::new(ProjectId::system(), "Engineering");
    let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone());
    write.add_members.push(GroupMember::new(group.id, alice.id));
    write.add_members.push(GroupMember::new(group.id, bob.id));
    storage
        .write_directory_group(&write, AuditEntry::system("test", "group").into())
        .await
        .unwrap();
    let created = group_event(event_types::SCIM_GROUP_CREATED, group.id);
    assert_eq!(first(&worker, &created).await, Settlement::Done);

    let mut renamed = group.clone();
    renamed.name = "Platform".into();
    let mut rename = DirectoryGroupWrite::new(DirectoryWriteMode::Update, renamed);
    rename.remove_members.push(bob.id);
    storage
        .write_directory_group(&rename, AuditEntry::system("test", "rename").into())
        .await
        .unwrap();
    let updated = group_event(event_types::SCIM_GROUP_UPDATED, group.id);
    assert_eq!(first(&worker, &updated).await, Settlement::Done);

    let d = down.lock().unwrap();
    assert_eq!(d.groups.len(), 1, "the renamed group was created again");
    let alice_id = d
        .users
        .iter()
        .find(|u| u["userName"] == json!("alice"))
        .unwrap()["id"]
        .clone();
    assert_eq!(d.groups[0]["displayName"], json!("Platform"));
    assert_eq!(
        d.groups[0]["members"],
        json!([{"value": alice_id}]),
        "the member removed with the rename kept the downstream membership"
    );
}

/// A failure a later attempt may cure is left for the redelivery, after the
/// target's backoff, without a dead letter; at the target's last attempt it
/// is recorded.
#[tokio::test]
async fn test_a_transient_failure_is_retried_then_recorded() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    down.lock().unwrap().fail_with = Some(503);
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);

    assert_eq!(
        first(&worker, &provisioned).await,
        Settlement::Retry(Duration::from_secs(1))
    );
    assert_eq!(
        worker.process(&provisioned, 2, &Hold::unbounded()).await,
        Settlement::Retry(Duration::from_secs(2))
    );
    assert_eq!(dead_letters(&storage, &t).await, 0, "recorded too early");
    assert_eq!(
        worker.process(&provisioned, 3, &Hold::unbounded()).await,
        Settlement::Done
    );
    assert_eq!(dead_letters(&storage, &t).await, 1);
}

/// A target's attempts are its own: an event delivered many times for other
/// reasons (another target's retries, a lost hold) does not use them up, so
/// a target's first transient failure is retried, and only its own last
/// attempt records the failure.
#[tokio::test]
async fn test_a_targets_attempts_are_its_own() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    down.lock().unwrap().fail_with = Some(503);
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);

    for delivery in 5..7 {
        assert!(matches!(
            worker
                .process(&provisioned, delivery, &Hold::unbounded())
                .await,
            Settlement::Retry(_)
        ));
        assert_eq!(dead_letters(&storage, &t).await, 0, "recorded too early");
    }
    assert_eq!(
        worker.process(&provisioned, 7, &Hold::unbounded()).await,
        Settlement::Done
    );
    assert_eq!(dead_letters(&storage, &t).await, 1);
}

/// A mapped user's failure is counted on its mapping in the commit that
/// records it: while the mapping cannot be written nothing of the failure
/// is (no dead letter, no outcome) and the event is retried, and once it
/// can, the dead letter and the count land together.
#[tokio::test]
async fn test_a_failure_is_counted_with_its_dead_letter() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);
    assert_eq!(first(&worker, &provisioned).await, Settlement::Done);

    down.lock().unwrap().fail_with = Some(400);
    sqlx::query(
        "CREATE TRIGGER unwritable BEFORE UPDATE ON scim_outbound_records \
         BEGIN SELECT RAISE(ABORT, 'unwritable'); END",
    )
    .execute(storage.pool())
    .await
    .unwrap();
    let updated = user_event(event_types::SCIM_USER_UPDATED, alice.id);
    assert_eq!(
        first(&worker, &updated).await,
        Settlement::Retry(UNRECORDED_RETRY),
        "settled with the failure uncounted"
    );
    assert_eq!(dead_letters(&storage, &t).await, 0);

    sqlx::query("DROP TRIGGER unwritable")
        .execute(storage.pool())
        .await
        .unwrap();
    assert_eq!(
        worker.process(&updated, 2, &Hold::unbounded()).await,
        Settlement::Done
    );
    assert_eq!(dead_letters(&storage, &t).await, 1);
    let mapped = storage
        .get_scim_outbound_record(t.id, alice.id.into_uuid(), OutboundEntityType::User)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapped.failure_count, 1);
    assert!(mapped.last_error.is_some());
}

/// A delivery whose hold would end before a request does sends nothing and
/// leaves the event for its redelivery, recording no failure.
#[tokio::test]
async fn test_an_unheld_delivery_sends_nothing() {
    let (endpoint, down) = downstream().await;
    let t = target("app", true, &endpoint);
    let (storage, worker) = worker(vec![t.clone()]).await;
    let alice = stored_profile(&storage, "alice").await;
    let (_deadline, hold) = tokio::sync::watch::channel(tokio::time::Instant::now());
    let provisioned = user_event(event_types::SCIM_USER_PROVISIONED, alice.id);

    assert_eq!(
        worker.process(&provisioned, 9, &Hold::until(hold)).await,
        Settlement::Retry(NOT_HELD_RETRY)
    );
    assert_eq!(
        down.lock().unwrap().requests,
        0,
        "a request went out unheld"
    );
    assert_eq!(dead_letters(&storage, &t).await, 0);
}
