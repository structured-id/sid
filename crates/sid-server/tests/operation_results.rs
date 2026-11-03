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

/// A creation that issues a one-time secret, retried after its response was
/// lost, answers with the token it created and no value (SID keeps only its
/// hash) and creates no second token.
#[tokio::test]
async fn test_initial_access_token_retry_answers_without_its_value() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let create = || CreateInitialAccessTokenRequest {
        project_id: sid_core::models::ProjectId::system().0.to_string(),
        max_clients: 1,
        ..Default::default()
    };

    let first = svc
        .project
        .create_initial_access_token(keyed(create(), &token, Some("op-iat")))
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .project
        .create_initial_access_token(keyed(create(), &token, Some("op-iat")))
        .await
        .unwrap()
        .into_inner();

    assert!(!first.token_value.is_empty());
    assert!(retry.token_value.is_empty());
    assert_eq!(retry.token, first.token);
    let listed = svc
        .project
        .list_initial_access_tokens(keyed(
            ListInitialAccessTokensRequest {
                project_id: sid_core::models::ProjectId::system().0.to_string(),
            },
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.tokens.len(), 1);
}

/// An application whose client gets a one-time secret, retried after its
/// response was lost, answers with the application it created and no secret,
/// and creates no second application.
#[tokio::test]
async fn test_create_application_retry_answers_without_its_secret() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let create = || CreateApplicationRequest {
        project_id: sid_core::models::ProjectId::system().0.to_string(),
        name: "billing".to_string(),
        client: Some(ClientRoleSettings {
            // A web client (the unspecified type) gets a secret.
            redirect_uris: vec!["https://app.sid.example.com/cb".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    let first = svc
        .project
        .create_application(keyed(create(), &token, Some("op-app")))
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .project
        .create_application(keyed(create(), &token, Some("op-app")))
        .await
        .unwrap()
        .into_inner();

    assert!(!first.client_secret.is_empty());
    assert!(retry.client_secret.is_empty());
    assert_eq!(retry.application, first.application);
    let listed = svc
        .project
        .list_applications(keyed(
            ListApplicationsRequest {
                project_id: sid_core::models::ProjectId::system().0.to_string(),
                ..Default::default()
            },
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        listed
            .applications
            .iter()
            .filter(|a| a.name == "billing")
            .count(),
        1
    );
}

/// A suspension completes, the profile is reactivated, then the suspension's
/// lost response is retried: the retry answers as the suspension did and
/// neither suspends the profile again nor ends its new access.
#[tokio::test]
async fn test_admin_suspension_retry_keeps_a_later_reactivation() {
    use sid_proto::sid::v1::admin_service_server::AdminService;
    let user = sid_core::models::Profile::new(Some("suspended_retry"));
    let svc = TestServices::new(MockStorage::new().with_profile(user.clone()));
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let status = |s: sid_proto::sid::v1::ProfileStatus| AdminUpdateProfileRequest {
        profile_id: user.id.to_string(),
        profile_status: s as i32,
        ..Default::default()
    };
    let stored = || async {
        svc.storage
            .get_profile(user.id)
            .await
            .unwrap()
            .unwrap()
            .status
    };

    let first = svc
        .admin
        .admin_update_profile(keyed(
            status(sid_proto::sid::v1::ProfileStatus::Suspended),
            &token,
            Some("op-suspend"),
        ))
        .await
        .unwrap()
        .into_inner();
    svc.admin
        .admin_update_profile(keyed(
            status(sid_proto::sid::v1::ProfileStatus::Active),
            &token,
            Some("op-activate"),
        ))
        .await
        .unwrap();
    let retry = svc
        .admin
        .admin_update_profile(keyed(
            status(sid_proto::sid::v1::ProfileStatus::Suspended),
            &token,
            Some("op-suspend"),
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry, first);
    assert_eq!(
        stored().await,
        sid_core::models::ProfileStatus::Active,
        "the retry suspended the profile again"
    );
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
