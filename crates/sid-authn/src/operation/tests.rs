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

/// Regression: a commit refused for room the store does not have reached
/// the caller as an internal failure. A result larger than the store keeps
/// is answered as exhausted, and its effect is not committed.
#[tokio::test]
async fn test_a_result_too_large_to_keep_is_exhausted_and_commits_nothing() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let limit = storage
        .operation_period_policy()
        .await
        .unwrap()
        .result_bytes;
    let context = OperationContext::new(
        OperationKey::parse("k-large").unwrap(),
        period(&storage).await,
    );
    let command = KeyedCommand::of::<CreateProject>("profile:a", context, &create("p"));
    let project = Project::new("p", None);
    let outcome = command
        .execute(&storage, || async {
            let ctx: MutationContext = AuditEntry::system("test", "project").into();
            storage
                .create_project(
                    &project,
                    ctx.with_operation(command.completion(vec![0; limit as usize + 1])),
                )
                .await
                .map_err(Effect::<()>::Store)?;
            Ok(sid_proto::sid::v1::projects::Project::default())
        })
        .await;
    assert!(
        matches!(
            outcome,
            Err(CommandError::Operation(OperationError::Exhausted(_)))
        ),
        "{outcome:?}"
    );
    assert!(storage.get_project(project.id).await.unwrap().is_none());
    assert_eq!(command.completed(&storage).await.unwrap(), None);
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

/// Upkeep retires a period once its retention after its acceptance end
/// passed, under the persisted policy, with its completions: a retry of a
/// command completed in it is refused, never answered or executed again.
/// Before that point the period and its completion stay.
#[tokio::test]
async fn test_upkeep_retires_periods_past_their_retention() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let policy = storage.operation_period_policy().await.unwrap();
    let issued = storage
        .current_operation_period(Utc::now(), policy.acceptance)
        .await
        .unwrap();
    let context = OperationContext::new(OperationKey::parse("k-upkeep").unwrap(), issued.period);
    let command = KeyedCommand::of::<CreateProject>("profile:a", context, &create("p"));
    commit(&storage, &command, b"done").await;

    assert_eq!(upkeep(&storage, issued.accepted_until).await, 0);
    assert_eq!(
        command.completed(&storage).await.unwrap().as_deref(),
        Some(&b"done"[..])
    );

    let past = issued.accepted_until + policy.retention + Duration::seconds(1);
    assert_eq!(upkeep(&storage, past).await, 1);
    assert!(
        matches!(
            command.completed(&storage).await,
            Err(OperationError::PeriodRefused(
                OperationPeriodRefusal::Retired
            ))
        ),
        "the retired period admits nothing"
    );
}

/// The identifier of what a keyed creation creates is a fresh UUIDv7 bound to
/// the command: every attempt of it, concurrent ones included, resolves the
/// same one; the key with other inputs is a conflict and binds nothing.
#[tokio::test]
async fn test_resource_id_is_allocated_once_per_command() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let period = period(&storage).await;
    let context = OperationContext::new(OperationKey::parse("k-create").unwrap(), period);
    let command = || KeyedCommand::of::<CreateProject>("profile:a", context.clone(), &create("p"));

    let (first, second) = (command(), command());
    let (a, b) = tokio::join!(first.resource_id(&storage), second.resource_id(&storage));
    let id = a.unwrap();
    assert_eq!(b.unwrap(), id, "concurrent attempts share one identifier");
    assert_eq!(id.get_version_num(), 7, "allocated in its domain format");
    assert_eq!(command().resource_id(&storage).await.unwrap(), id);

    let other = KeyedCommand::of::<CreateProject>("profile:a", context.clone(), &create("q"));
    assert!(matches!(
        other.resource_id(&storage).await,
        Err(OperationError::KeyConflict)
    ));
    // Another caller's key of the same name is another command.
    let theirs = KeyedCommand::of::<CreateProject>("profile:b", context, &create("p"));
    assert_ne!(theirs.resource_id(&storage).await.unwrap(), id);
}

/// A command with an effect outside its store learns whether it is the
/// first attempt: exactly one of concurrent attempts is, and none after it,
/// so a later attempt never repeats an effect the first may have made.
#[tokio::test]
async fn test_only_the_first_attempt_of_a_command_is_first() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let period = period(&storage).await;
    let context = OperationContext::new(OperationKey::parse("k-send").unwrap(), period);
    let command = || KeyedCommand::of::<CreateProject>("profile:a", context.clone(), &create("p"));

    let (first, second) = (command(), command());
    let (a, b) = tokio::join!(
        first.first_attempt(&storage),
        second.first_attempt(&storage)
    );
    assert_ne!(
        a.unwrap(),
        b.unwrap(),
        "exactly one concurrent attempt is the first"
    );
    assert!(!command().first_attempt(&storage).await.unwrap());

    let other = KeyedCommand::of::<CreateProject>("profile:a", context, &create("q"));
    assert!(matches!(
        other.first_attempt(&storage).await,
        Err(OperationError::KeyConflict)
    ));
}

/// A command named with a period the store retired binds nothing.
#[tokio::test]
async fn test_resource_id_under_a_retired_period_is_refused() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let policy = storage.operation_period_policy().await.unwrap();
    let issued = storage
        .current_operation_period(Utc::now(), policy.acceptance)
        .await
        .unwrap();
    let past = issued.accepted_until + policy.retention + Duration::seconds(1);
    assert_eq!(upkeep(&storage, past).await, 1);
    let context = OperationContext::new(OperationKey::parse("k-late").unwrap(), issued.period);
    let command = KeyedCommand::of::<CreateProject>("profile:a", context, &create("p"));
    assert!(matches!(
        command.resource_id(&storage).await,
        Err(OperationError::PeriodRefused(
            OperationPeriodRefusal::Retired
        ))
    ));
}

/// Every attempt of one command names the same correlation key; another
/// key, period, caller or method names another one.
#[test]
fn test_command_id_is_the_commands_own() {
    let context = |key: &str, period| {
        OperationContext::new(
            OperationKey::parse(key).unwrap(),
            OperationPeriod::new(period),
        )
    };
    let id = |namespace: &str, context, request: &CreateProjectRequest| {
        KeyedCommand::of::<CreateProject>(namespace, context, request).command_id()
    };
    let first = id("profile:a", context("k", 1), &create("p"));
    assert_eq!(first, id("profile:a", context("k", 1), &create("p")));
    // The inputs are not part of it: a retry with other inputs conflicts on
    // its key rather than creating something else under another identifier.
    assert_eq!(first, id("profile:a", context("k", 1), &create("q")));
    assert_ne!(first, id("profile:a", context("k2", 1), &create("p")));
    assert_ne!(first, id("profile:a", context("k", 2), &create("p")));
    assert_ne!(first, id("profile:b", context("k", 1), &create("p")));
    let other_method = KeyedCommand::of::<DeleteProject>(
        "profile:a",
        context("k", 1),
        &DeleteProjectRequest::default(),
    );
    assert_ne!(first, other_method.command_id());
    assert_eq!(first.get_version_num(), 5);
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
