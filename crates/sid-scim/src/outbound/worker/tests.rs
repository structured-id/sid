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
    /// Answer every request with this status, changing nothing.
    fail_with: Option<u16>,
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
    ) -> Result<Json<Value>, StatusCode> {
        admit(&state).await?;
        let filter = query.get("filter").ok_or(StatusCode::BAD_REQUEST)?;
        let (attribute, literal) = filter.split_once(" eq ").ok_or(StatusCode::BAD_REQUEST)?;
        let wanted: String = serde_json::from_str(literal).map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut d = state.lock().unwrap();
        let found: Vec<Value> = d
            .resources(&kind)
            .iter()
            .filter(|r| r[attribute] == json!(wanted))
            .cloned()
            .collect();
        Ok(Json(
            json!({"totalResults": found.len(), "Resources": found}),
        ))
    }
    async fn modify(
        State(state): State<Shared>,
        Path((kind, id)): Path<(String, String)>,
        Json(body): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        admit(&state).await?;
        let mut d = state.lock().unwrap();
        let resource = d
            .resources(&kind)
            .iter_mut()
            .find(|r| r["id"] == json!(id))
            .ok_or(StatusCode::NOT_FOUND)?;
        for op in body["Operations"]
            .as_array()
            .ok_or(StatusCode::BAD_REQUEST)?
        {
            let path = op["path"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
            match op["op"].as_str() {
                Some("replace") => resource[path] = op["value"].clone(),
                Some("remove") => {
                    resource.as_object_mut().unwrap().remove(path);
                }
                _ => return Err(StatusCode::BAD_REQUEST),
            }
        }
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
    assert_eq!(dead_letters(&storage, &t).await, 0, "recorded too early");
    assert_eq!(
        worker.process(&provisioned, 3, &Hold::unbounded()).await,
        Settlement::Done
    );
    assert_eq!(dead_letters(&storage, &t).await, 1);
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
