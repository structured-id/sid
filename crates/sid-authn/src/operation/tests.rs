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

/// A command named by its method's own canonical inputs is the same command
/// for the same inputs and conflicts with other ones, and its completion
/// names the method and the period like any keyed command's.
#[tokio::test]
async fn test_a_command_of_canonical_inputs_resolves_like_any_keyed_command() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let period = period(&storage).await;
    let context = OperationContext::new(OperationKey::parse("k-inputs").unwrap(), period);
    let command =
        KeyedCommand::of_inputs::<CreateProject>("profile:a", context.clone(), b"set:a,b".to_vec());
    let completion = command.completion(Vec::new());
    assert_eq!(completion.method, CreateProject::METHOD);
    assert_eq!(completion.period, Some(period));
    assert_eq!(command.completed(&storage).await.unwrap(), None);

    commit(&storage, &command, b"done").await;
    let retry =
        KeyedCommand::of_inputs::<CreateProject>("profile:a", context.clone(), b"set:a,b".to_vec());
    assert_eq!(
        retry.completed(&storage).await.unwrap().as_deref(),
        Some(&b"done"[..])
    );
    let other = KeyedCommand::of_inputs::<CreateProject>("profile:a", context, b"set:c".to_vec());
    assert!(matches!(
        other.completed(&storage).await,
        Err(OperationError::KeyConflict)
    ));
}

/// The same request decoded twice names the same command: a map field's
/// entries are encoded in one order, so a retry of a request carrying
/// metadata is not mistaken for another command.
#[test]
fn test_equal_requests_with_maps_have_one_fingerprint() {
    use prost::Message;
    use sid_proto::keyed::admin::enrollment_service::CreateInvite;
    use sid_proto::sid::v1::admin::CreateInviteRequest;
    let request = CreateInviteRequest {
        metadata: (0..16)
            .map(|i| (format!("key-{i}"), format!("value-{i}")))
            .collect(),
        ..Default::default()
    };
    let wire = request.encode_to_vec();
    let context = OperationContext::new(OperationKey::parse("k").unwrap(), OperationPeriod::new(1));
    let fingerprint = || {
        let decoded = CreateInviteRequest::decode(wire.as_slice()).unwrap();
        KeyedCommand::of::<CreateInvite>("profile:a", context.clone(), &decoded)
            .completion(Vec::new())
            .fingerprint
    };
    let first = fingerprint();
    for _ in 0..8 {
        assert_eq!(fingerprint(), first);
    }
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

/// An attempt refused because a concurrent attempt of the same command
/// committed first (a limit counted before the key) answers with that
/// attempt's recorded result, not with its own refusal.
#[tokio::test]
async fn test_a_refusal_after_the_command_completed_answers_its_result() {
    use prost::Message;
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let context =
        OperationContext::new(OperationKey::parse("k-4").unwrap(), period(&storage).await);
    let command = KeyedCommand::of::<CreateProject>("profile:a", context, &create("p"));
    let winner = create("winner");

    let answered: CreateProjectRequest = command
        .execute(&storage, || async {
            // The concurrent attempt commits while this one runs.
            commit(&storage, &command, &winner.encode_to_vec()).await;
            Err::<CreateProjectRequest, _>(Effect::Refused(OperationError::OutcomeUnknown))
        })
        .await
        .expect("the completed command's result");
    assert_eq!(answered, winner);
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
