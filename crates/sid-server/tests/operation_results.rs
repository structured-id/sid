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
