// SPDX-License-Identifier: AGPL-3.0-only
//! Durable operation results: a keyed command's completion commits with its
//! effect, once per key within its namespace.

use sid_core::Error;
use sid_core::models::{MutationContext, OperationCompletion, OperationKey, Project, ProjectId};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

const METHOD: &str = "sid.v1.ProjectService/CreateProject";

fn key() -> OperationKey {
    OperationKey::parse(&Uuid::new_v4().to_string()).unwrap()
}

fn namespace() -> String {
    format!("profile:{}", Uuid::now_v7())
}

fn completion(namespace: &str, key: &OperationKey, inputs: &[u8]) -> OperationCompletion {
    OperationCompletion::new(namespace, key.clone(), METHOD, inputs, inputs.to_vec())
}

fn keyed(namespace: &str, key: &OperationKey, inputs: &[u8]) -> MutationContext {
    test_audit().with_operation(completion(namespace, key, inputs))
}

async fn project_exists(backend: &dyn StorageBackend, project: &Project) -> bool {
    backend.get_project(project.id).await.unwrap().is_some()
}

/// The completion commits with the effect and resolves the key afterwards.
pub async fn test_operation_completion_commits_with_effect(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let project = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, keyed(&ns, &key, b"inputs"))
        .await
        .unwrap();

    let record = backend
        .get_operation_result(&ns, &key)
        .await
        .unwrap()
        .expect("recorded");
    assert!(record.matches(METHOD, b"inputs"));
    assert!(!record.matches(METHOD, b"other"));
    assert_eq!(record.completion.result, b"inputs");
    assert!(project_exists(backend, &project).await);
}

/// A second commit under a completed key commits nothing, whatever it
/// carries, and says so; the same key in another namespace is its own.
pub async fn test_completed_operation_commits_nothing(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let first = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&first, keyed(&ns, &key, b"inputs"))
        .await
        .unwrap();

    let retry = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    let err = backend
        .create_project(&retry, keyed(&ns, &key, b"inputs"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OperationCompleted(_)), "{err:?}");
    assert!(
        !project_exists(backend, &retry).await,
        "a retry executed again"
    );

    let elsewhere = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&elsewhere, keyed(&namespace(), &key, b"inputs"))
        .await
        .unwrap();
    assert!(project_exists(backend, &elsewhere).await);
}

/// Two attempts of one command at once: one commits, the other commits
/// nothing.
pub async fn test_concurrent_duplicate_operation_commits_once(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let a = Project::new(format!("op_a_{}", Uuid::now_v7().simple()), None);
    let b = Project::new(format!("op_b_{}", Uuid::now_v7().simple()), None);
    let (ra, rb) = tokio::join!(
        backend.create_project(&a, keyed(&ns, &key, b"inputs")),
        backend.create_project(&b, keyed(&ns, &key, b"inputs")),
    );
    assert_eq!(
        usize::from(ra.is_ok()) + usize::from(rb.is_ok()),
        1,
        "{ra:?} {rb:?}"
    );
    let loser_err = if ra.is_ok() { rb } else { ra }.unwrap_err();
    assert!(
        matches!(loser_err, Error::OperationCompleted(_)),
        "{loser_err:?}"
    );
    assert_eq!(
        usize::from(project_exists(backend, &a).await)
            + usize::from(project_exists(backend, &b).await),
        1
    );
}

/// A completion leaves in the export and comes back through import with its
/// original time; importing it again writes nothing, and the imported key
/// refuses a second execution like any completed key.
pub async fn test_operation_results_travel_between_stores(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let project = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, keyed(&ns, &key, b"inputs"))
        .await
        .unwrap();
    let exported = backend.export_operation_results().await.unwrap();
    let mine = exported
        .iter()
        .find(|r| r.completion.namespace == ns && r.completion.key == key)
        .expect("exported")
        .clone();
    assert!(
        !backend.import_operation_result(&mine).await.unwrap(),
        "an existing completion is kept"
    );

    let mut moved = mine.clone();
    moved.completion.namespace = namespace();
    moved.completed_at -= chrono::Duration::days(1);
    assert!(backend.import_operation_result(&moved).await.unwrap());
    let restored = backend
        .get_operation_result(&moved.completion.namespace, &key)
        .await
        .unwrap()
        .expect("imported");
    assert_eq!(restored.completion, moved.completion);
    assert_eq!(
        restored.completed_at.timestamp_millis(),
        moved.completed_at.timestamp_millis()
    );

    let retry = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    let err = backend
        .create_project(&retry, keyed(&moved.completion.namespace, &key, b"inputs"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OperationCompleted(_)), "{err:?}");
}

/// A mutation that fails records no completion: the key stays free.
pub async fn test_failed_mutation_records_no_completion(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let (ns, key) = (namespace(), key());
    let refused = backend
        .delete_project(ProjectId::system(), keyed(&ns, &key, b"inputs"))
        .await;
    assert!(refused.is_err());
    assert!(
        backend
            .get_operation_result(&ns, &key)
            .await
            .unwrap()
            .is_none()
    );
}
