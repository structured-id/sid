use super::*;
use sid_core::models::{
    AttributeMapping, GroupPushConfig, OutboundAuthConfig, OutboundSyncConfig, ProjectId,
};
use sid_plugin::WorkStore;
use sid_plugin::event_bus::InProcessEventBus;
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
    let worker = ScimOutboundWorker::new(
        storage.clone(),
        Arc::new(InProcessEventBus::new()),
        targets,
        100,
    );
    (storage, worker)
}

/// A provisioning event whose profile does not exist: every dispatch of it
/// fails.
fn undeliverable() -> Event {
    Event::new("sid-scim", event_types::SCIM_USER_PROVISIONED)
        .with_data(serde_json::json!({"profile_id": Uuid::now_v7().to_string()}))
}

/// An accepted event is owed to each enabled target as its own job, none to
/// a disabled one, and accepting it again (a redelivery) stores nothing new.
#[tokio::test]
async fn test_accepting_owes_one_job_per_enabled_target() {
    let (a, b, off) = (target("a", true), target("b", true), target("off", false));
    let (storage, worker) = worker(vec![a.clone(), b.clone(), off.clone()]).await;
    let event = undeliverable();

    assert_eq!(worker.accept(&event).await, Settlement::Done);
    assert_eq!(worker.accept(&event).await, Settlement::Done);
    for owed in [&a, &b] {
        let job = storage
            .get_work(dispatch_job(&event, owed.id).id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no job for {}", owed.display_name));
        assert_eq!(job.state, sid_core::models::WorkState::Pending);
    }
    assert!(
        storage
            .get_work(dispatch_job(&event, off.id).id)
            .await
            .unwrap()
            .is_none(),
        "a disabled target was owed the event"
    );
    let jobs = storage.export_work().await.unwrap();
    assert_eq!(jobs.len(), 2, "a redelivered event stored a second job");
}

fn claimed(work: NewWork) -> ClaimedWork {
    ClaimedWork {
        id: work.id,
        kind: work.kind,
        payload: work.payload,
        attempt: 1,
        max_attempts: work.max_attempts,
        generation: 1,
        expires_at: None,
    }
}

/// A target's job dispatches to that target only: its failure is recorded
/// in the dead-letter store and ends the job, and the other target's job is
/// untouched by it. A job for a target no longer configured is done.
#[tokio::test]
async fn test_a_job_dispatches_to_its_own_target_only() {
    let (a, b) = (target("a", true), target("b", true));
    let (storage, worker) = worker(vec![a.clone(), b.clone()]).await;
    let event = undeliverable();
    worker.accept(&event).await;

    let outcome = worker.handle(&claimed(dispatch_job(&event, a.id))).await;
    assert_eq!(outcome, WorkOutcome::Done(Some("failure recorded".into())));
    let dead = storage.list_outbound_dlq_entries(a.id).await.unwrap();
    assert_eq!(dead.len(), 1, "the failure was not recorded");
    assert!(
        storage
            .list_outbound_dlq_entries(b.id)
            .await
            .unwrap()
            .is_empty(),
        "the other target was dispatched to"
    );

    let removed = target("gone", true);
    let outcome = worker
        .handle(&claimed(dispatch_job(&event, removed.id)))
        .await;
    assert_eq!(
        outcome,
        WorkOutcome::Done(Some("target no longer configured".into()))
    );
}
