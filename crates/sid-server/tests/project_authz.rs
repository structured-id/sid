// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of ProjectService: projects, applications (OAuth clients and
//! their secrets), project roles and registration tokens are managed by an
//! administrator. Without this, anyone could register an OAuth client or mint
//! an initial access token for dynamic client registration.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, issue_token};
use sid_core::models::{Profile, ProjectId};
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn new_app() -> CreateApplicationRequest {
    CreateApplicationRequest {
        project_id: ProjectId::system().0.to_string(),
        name: "rogue".to_string(),
        client: Some(ClientRoleSettings {
            redirect_uris: vec!["https://attacker.example.com/cb".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn new_iat() -> CreateInitialAccessTokenRequest {
    CreateInitialAccessTokenRequest {
        project_id: ProjectId::system().0.to_string(),
        ..Default::default()
    }
}

/// Regression (#881): without a token nothing is created or listed.
#[tokio::test]
async fn test_project_rpcs_require_a_token() {
    let svc = TestServices::new(MockStorage::new());
    let p = &svc.project;
    let codes = [
        p.create_project(Request::new(CreateProjectRequest {
            name: "x".to_string(),
            ..Default::default()
        }))
        .await
        .err()
        .map(|e| e.code()),
        p.list_projects(Request::new(ListProjectsRequest::default()))
            .await
            .err()
            .map(|e| e.code()),
        p.create_application(Request::new(new_app()))
            .await
            .err()
            .map(|e| e.code()),
        p.create_initial_access_token(Request::new(new_iat()))
            .await
            .err()
            .map(|e| e.code()),
    ];
    for (i, code) in codes.into_iter().enumerate() {
        assert_eq!(code, Some(Code::Unauthenticated), "rpc #{i}");
    }
}

/// Regression (#881): a signed-in user without the administrator role cannot
/// register an OAuth client or mint a registration token.
#[tokio::test]
async fn test_project_rpcs_refuse_a_non_admin() {
    let user = Profile::new(Some("mallory"));
    let svc = TestServices::new(MockStorage::new().with_profile(user.clone()));
    let token = issue_token(&svc.jwt, &user, &["openid".to_string()]);
    let p = &svc.project;
    let codes = [
        p.create_application(authed(new_app(), &token))
            .await
            .err()
            .map(|e| e.code()),
        p.create_initial_access_token(authed(new_iat(), &token))
            .await
            .err()
            .map(|e| e.code()),
        p.list_applications(authed(
            ListApplicationsRequest {
                project_id: ProjectId::system().0.to_string(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .err()
        .map(|e| e.code()),
    ];
    for (i, code) in codes.into_iter().enumerate() {
        assert_eq!(code, Some(Code::PermissionDenied), "rpc #{i}");
    }
}

/// An initial access token records the administrator who created it, not a
/// placeholder: the registrations it admits are traced back to that Profile.
#[tokio::test]
async fn test_iat_records_its_creator() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let admin = sid_core::models::ProfileId::generate();
    let token = issue_admin_token(&svc.jwt, admin);
    let created = svc
        .project
        .create_initial_access_token(authed(new_iat(), &token))
        .await
        .expect("admin creates")
        .into_inner()
        .token
        .expect("token");
    assert_eq!(created.created_by, admin.to_string());
}

/// An administrator creates and lists projects.
#[tokio::test]
async fn test_project_rpcs_allow_an_administrator() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    let mut create = authed(
        CreateProjectRequest {
            name: "billing".to_string(),
            ..Default::default()
        },
        &token,
    );
    create.metadata_mut().insert(
        sid_authn::operation::OPERATION_KEY_HEADER,
        "create-billing".parse().unwrap(),
    );
    svc.project
        .create_project(create)
        .await
        .expect("admin creates");
    svc.project
        .list_projects(authed(ListProjectsRequest::default(), &token))
        .await
        .expect("admin lists");
}
