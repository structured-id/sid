use super::*;
use sid_core::models::{
    AttributeMapping, GroupPushConfig, OutboundAuthConfig, OutboundSyncConfig, ProjectId,
};
use sid_plugin::WorkStore;
use sid_plugin::event_bus::{InProcessEventBus, Settlement};
use sid_storage::sqlite::SqliteBackend;

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
}

#[test]
fn test_reactivate_patch_payload() {
    let patch = mapper::ScimPatchPayload::reactivate();
    assert_eq!(patch.operations.len(), 1);
    assert_eq!(patch.operations[0].op, "replace");
    assert_eq!(patch.operations[0].path.as_deref(), Some("active"));
    assert_eq!(patch.operations[0].value, Some(serde_json::json!(true)));
}

fn target(name: &str, enabled: bool) -> ScimOutboundTarget {
    ScimOutboundTarget {
        id: ScimOutboundTargetId::new(),
        client_id: format!("{name}-app"),
        project_id: ProjectId::system(),
        display_name: name.into(),
        // Nothing listens there: a dispatch fails at once.
        endpoint_url: "http://127.0.0.1:1/scim/v2".into(),
        auth: OutboundAuthConfig::Bearer {
            token_secret: "test-token".into(),
        },
        attribute_mapping: AttributeMapping::default(),
        group_push: GroupPushConfig::default(),
        sync_config: OutboundSyncConfig {
            max_retry_attempts: 3,
            retry_backoff_base_secs: 1,
        },
        enabled,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
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

/// A provisioning event whose profile does not exist: every dispatch of it
/// fails.
fn undeliverable() -> Event {
    Event::new("sid-scim", event_types::SCIM_USER_PROVISIONED)
        .with_data(serde_json::json!({"profile_id": Uuid::now_v7().to_string()}))
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
    let (a, b, off) = (target("a", true), target("b", true), target("off", false));
    let (storage, worker) = worker(vec![a.clone(), b.clone(), off.clone()]).await;
    let event = undeliverable();

    for _ in 0..2 {
        assert_eq!(worker.process(&event).await, Settlement::Done);
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
    let (a, b) = (target("a", true), target("b", true));
    let (storage, worker) = worker(vec![a.clone(), b.clone()]).await;
    let event = undeliverable();
    assert!(worker.record_taken(&a, &event).await);

    assert_eq!(worker.process(&event).await, Settlement::Done);
    assert_eq!(dead_letters(&storage, &a).await, 0, "a took it twice");
    assert_eq!(dead_letters(&storage, &b).await, 1);
}

/// A target whose failure cannot be recorded leaves the event with the bus,
/// to come again; on its redelivery the target whose failure was recorded
/// is not dispatched to again.
#[tokio::test]
async fn test_an_unrecorded_failure_retries_only_its_target() {
    let a = target("a", true);
    // Not stored: its dead letter cannot be written.
    let ghost = target("ghost", true);
    let (storage, _) = worker(vec![a.clone()]).await;
    let worker = ScimOutboundWorker::new(
        storage.clone(),
        Arc::new(InProcessEventBus::new()),
        vec![a.clone(), ghost],
    );
    let event = undeliverable();

    for _ in 0..2 {
        assert_eq!(
            worker.process(&event).await,
            Settlement::Retry(UNRECORDED_RETRY)
        );
    }
    assert_eq!(
        dead_letters(&storage, &a).await,
        1,
        "a failure recorded twice"
    );
}
