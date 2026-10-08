use super::*;
use sid_core::grpc_error::extract_error_info;
use sid_core::models::{AuditEntry, MutationContext, Project};
use sid_storage::sqlite::SqliteBackend;

const METHOD: &str = "sid.v1.ProjectService/CreateProject";

fn metadata(value: Option<&str>) -> MetadataMap {
    let mut map = MetadataMap::new();
    if let Some(v) = value {
        map.insert(OPERATION_KEY_HEADER, v.parse().unwrap());
    }
    map
}

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

#[test]
fn test_required_key_reads_header() {
    let key = required_key(&metadata(Some("k-1"))).unwrap();
    assert_eq!(key.as_str(), "k-1");
}

/// A missing key is refused before any effect, as is a malformed one.
#[test]
fn test_required_key_refuses_missing_and_malformed() {
    let missing = required_key(&metadata(None)).unwrap_err();
    assert_eq!(missing.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&missing), "REQUIRED_FIELD_MISSING");

    let long = "k".repeat(300);
    let malformed = required_key(&metadata(Some(&long))).unwrap_err();
    assert_eq!(reason(&malformed), "INVALID_FIELD_VALUE");
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

/// A completed command answers its retry with the recorded result; the
/// same key with other inputs or another method is a conflict.
#[tokio::test]
async fn test_completed_resolves_retry_and_refuses_reuse() {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let key = OperationKey::parse("k-2").unwrap();
    let command = KeyedCommand::new("profile:a", key.clone(), METHOD, b"inputs".to_vec());
    assert_eq!(command.completed(&storage).await.unwrap(), None);

    commit(&storage, &command, b"result").await;
    assert_eq!(
        command.completed(&storage).await.unwrap().as_deref(),
        Some(&b"result"[..])
    );

    let other_inputs = KeyedCommand::new("profile:a", key.clone(), METHOD, b"other".to_vec());
    let conflict = other_inputs.completed(&storage).await.unwrap_err();
    assert_eq!(conflict.code(), tonic::Code::AlreadyExists);
    assert_eq!(reason(&conflict), "OPERATION_KEY_CONFLICT");

    let other_method = KeyedCommand::new(
        "profile:a",
        key.clone(),
        "sid.v1.ProjectService/DeleteProject",
        b"inputs".to_vec(),
    );
    assert!(other_method.completed(&storage).await.is_err());

    // Another actor's namespace does not see the record.
    let other_actor = KeyedCommand::new("profile:b", key, METHOD, b"inputs".to_vec());
    assert_eq!(other_actor.completed(&storage).await.unwrap(), None);
}
