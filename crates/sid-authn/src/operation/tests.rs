use super::*;
use chrono::{Duration, Utc};
use sid_core::models::{AuditEntry, MutationContext, Project};
use sid_plugin::StorageBackend;
use sid_proto::keyed::projects::project_service::{CreateProject, DeleteProject};
use sid_proto::sid::v1::projects::{CreateProjectRequest, DeleteProjectRequest};
use sid_storage::sqlite::SqliteBackend;

async fn period(storage: &SqliteBackend) -> OperationPeriod {
    storage
        .current_operation_period(Utc::now(), Duration::hours(1))
        .await
        .unwrap()
        .period
}

fn create(name: &str) -> CreateProjectRequest {
    CreateProjectRequest {
        name: name.into(),
        ..Default::default()
    }
}

async fn commit(storage: &SqliteBackend, command: &KeyedCommand, result: &[u8]) {
    let ctx: MutationContext = AuditEntry::system("test", "project").into();
    storage
        .create_project(
            &Project::new("p", None),
            ctx.with_operation(command.completion(result.to_vec())),
        )
        .await
        .unwrap();
}

/// A completed command answers its retry with the recorded result; the same
/// key with other inputs, another method or another period is a conflict,
/// and another actor's namespace does not see the record.
#[tokio::test]
async fn test_completed_resolves_retry_and_refuses_reuse() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let period = period(&storage).await;
    let key = OperationKey::parse("k-2").unwrap();
    let context = OperationContext::new(key.clone(), period);
    let command = KeyedCommand::of::<CreateProject>("profile:a", context.clone(), &create("p"));
    assert_eq!(command.completed(&storage).await.unwrap(), None);

    commit(&storage, &command, b"result").await;
    assert_eq!(
        command.completed(&storage).await.unwrap().as_deref(),
        Some(&b"result"[..])
    );

    let other_inputs =
        KeyedCommand::of::<CreateProject>("profile:a", context.clone(), &create("q"));
    assert!(matches!(
        other_inputs.completed(&storage).await,
        Err(OperationError::KeyConflict)
    ));

    let other_method = KeyedCommand::of::<DeleteProject>(
        "profile:a",
        context.clone(),
        &DeleteProjectRequest::default(),
    );
    assert!(matches!(
        other_method.completed(&storage).await,
        Err(OperationError::KeyConflict)
    ));

    // The same key under another period is not a retry of this command.
    let later = OperationContext::new(key.clone(), OperationPeriod::new(period.get() + 1));
    let other_period = KeyedCommand::of::<CreateProject>("profile:a", later, &create("p"));
    assert!(matches!(
        other_period.completed(&storage).await,
        Err(OperationError::KeyConflict)
    ));

    let other_actor = KeyedCommand::of::<CreateProject>("profile:b", context, &create("p"));
    assert_eq!(other_actor.completed(&storage).await.unwrap(), None);
}

/// A command named with a period the store never issued commits nothing.
#[tokio::test]
async fn test_commit_under_unissued_period_is_refused() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let issued = period(&storage).await;
    let context = OperationContext::new(
        OperationKey::parse("k-3").unwrap(),
        OperationPeriod::new(issued.get() + 7),
    );
    let command = KeyedCommand::of::<CreateProject>("profile:a", context, &create("p"));
    let ctx: MutationContext = AuditEntry::system("test", "project").into();
    let before = storage.list_projects(0, 100).await.unwrap().len();
    let err = storage
        .create_project(
            &Project::new("p", None),
            ctx.with_operation(command.completion(Vec::new())),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            sid_core::Error::OperationPeriodRefused(OperationPeriodRefusal::NotIssued)
        ),
        "{err:?}"
    );
    assert_eq!(storage.list_projects(0, 100).await.unwrap().len(), before);
}

/// A ceremony's own record carries no period and resolves its own retry.
#[tokio::test]
async fn test_ceremony_record_resolves_without_period() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let key = OperationKey::parse("op-1").unwrap();
    let command = KeyedCommand::ceremony("password", key, "finish", b"record".to_vec());
    assert_eq!(command.completion(Vec::new()).period, None);
    commit(&storage, &command, b"done").await;
    assert_eq!(
        command.completed(&storage).await.unwrap().as_deref(),
        Some(&b"done"[..])
    );
}
