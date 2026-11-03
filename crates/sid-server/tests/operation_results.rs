// SPDX-License-Identifier: AGPL-3.0-only
//! Durable operation results: a keyed ordinary mutation retried after its
//! response was lost returns the original outcome and executes once.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token};
use sid_authn::operation::OPERATION_KEY_HEADER;
use sid_core::grpc_error::extract_error_info;
use sid_core::models::ProfileId;
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};

fn keyed<T>(msg: T, token: &str, key: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    if let Some(key) = key {
        req.metadata_mut()
            .insert(OPERATION_KEY_HEADER, key.parse().unwrap());
    }
    req
}

fn create(name: &str) -> CreateProjectRequest {
    CreateProjectRequest {
        name: name.to_string(),
        ..Default::default()
    }
}

async fn projects_named(svc: &TestServices, token: &str, name: &str) -> usize {
    svc.project
        .list_projects(keyed(ListProjectsRequest::default(), token, None))
        .await
        .unwrap()
        .into_inner()
        .projects
        .iter()
        .filter(|p| p.name == name)
        .count()
}

/// The response of CreateProject is lost after the commit; the caller
/// retries with the same key and gets the same project, and only one exists.
#[tokio::test]
async fn test_create_project_retry_returns_original_outcome() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());

    let first = svc
        .project
        .create_project(keyed(create("billing"), &token, Some("op-1")))
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .project
        .create_project(keyed(create("billing"), &token, Some("op-1")))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry.id, first.id);
    assert_eq!(projects_named(&svc, &token, "billing").await, 1);
}

/// A new command needs a new key: the same key with other inputs is refused
/// and changes nothing.
#[tokio::test]
async fn test_create_project_key_reused_for_other_inputs_conflicts() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    svc.project
        .create_project(keyed(create("billing"), &token, Some("op-2")))
        .await
        .unwrap();

    let err = svc
        .project
        .create_project(keyed(create("payroll"), &token, Some("op-2")))
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::AlreadyExists);
    assert_eq!(
        extract_error_info(&err).expect("ErrorInfo").0,
        "OPERATION_KEY_CONFLICT"
    );
    assert_eq!(projects_named(&svc, &token, "payroll").await, 0);
}

/// Without a key the method cannot promise a safe retry, so it refuses
/// before any effect.
#[tokio::test]
async fn test_create_project_without_key_is_refused() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let err = svc
        .project
        .create_project(keyed(create("billing"), &token, None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(projects_named(&svc, &token, "billing").await, 0);
}

fn rename(id: &str, name: &str) -> UpdateProjectRequest {
    UpdateProjectRequest {
        id: id.to_string(),
        name: Some(name.to_string()),
        ..Default::default()
    }
}

/// Edit A completes, a later edit B completes, then A's lost response is
/// retried: the retry answers with the project as A left it and does not
/// write A's name over B's (it applied A again).
#[tokio::test]
async fn test_update_project_retry_does_not_overwrite_a_later_edit() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let project = svc
        .project
        .create_project(keyed(create("billing"), &token, Some("op-c")))
        .await
        .unwrap()
        .into_inner();

    let a = svc
        .project
        .update_project(keyed(rename(&project.id, "ledger"), &token, Some("op-a")))
        .await
        .unwrap()
        .into_inner();
    svc.project
        .update_project(keyed(rename(&project.id, "invoices"), &token, Some("op-b")))
        .await
        .unwrap();
    let retry = svc
        .project
        .update_project(keyed(rename(&project.id, "ledger"), &token, Some("op-a")))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry, a);
    assert_eq!(retry.name, "ledger");
    assert_eq!(projects_named(&svc, &token, "invoices").await, 1);
    assert_eq!(projects_named(&svc, &token, "ledger").await, 0);
}

/// A deletion's lost response is retried: the retry answers as the deletion
/// did (it answered NOT_FOUND, the absence the deletion left).
#[tokio::test]
async fn test_delete_project_retry_answers_as_the_deletion() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let project = svc
        .project
        .create_project(keyed(create("scratch"), &token, Some("op-e")))
        .await
        .unwrap()
        .into_inner();
    let delete = || DeleteProjectRequest {
        id: project.id.clone(),
    };

    svc.project
        .delete_project(keyed(delete(), &token, Some("op-f")))
        .await
        .unwrap();
    svc.project
        .delete_project(keyed(delete(), &token, Some("op-f")))
        .await
        .expect("the retry answers as the deletion");

    assert_eq!(projects_named(&svc, &token, "scratch").await, 0);
    // A new deletion under a new key finds nothing to delete.
    let err = svc
        .project
        .delete_project(keyed(delete(), &token, Some("op-g")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
}

/// An edit without a key cannot promise a safe retry and changes nothing.
#[tokio::test]
async fn test_update_project_without_key_is_refused() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let project = svc
        .project
        .create_project(keyed(create("billing"), &token, Some("op-d")))
        .await
        .unwrap()
        .into_inner();
    let err = svc
        .project
        .update_project(keyed(rename(&project.id, "ledger"), &token, None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(projects_named(&svc, &token, "billing").await, 1);
}

/// Keys belong to the caller: another administrator's command under the
/// same key is its own command.
#[tokio::test]
async fn test_operation_keys_are_per_caller() {
    let svc = TestServices::new(MockStorage::new());
    let alice = issue_admin_token(&svc.jwt, ProfileId::generate());
    let bob = issue_admin_token(&svc.jwt, ProfileId::generate());
    let a = svc
        .project
        .create_project(keyed(create("billing"), &alice, Some("op-3")))
        .await
        .unwrap()
        .into_inner();
    let b = svc
        .project
        .create_project(keyed(create("billing"), &bob, Some("op-3")))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(a.id, b.id);
    assert_eq!(projects_named(&svc, &alice, "billing").await, 2);
}
