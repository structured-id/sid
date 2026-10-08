// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of AuthzService: roles, assignments, groups and policies are
//! managed only by an administrator, and a permission check answers only for
//! the caller's own subject. Without this, anyone reaching the endpoint could
//! add an allow-all policy and open every protected application.
//!
//! Requires sid-test-postgres on port 54399.

mod common;

use common::{issue_admin_token, issue_token, test_jwt};
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::models::{Profile, ProjectId};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz_service_server::AuthzService;
use sid_proto::sid::v1::*;
use sid_storage::PostgresBackend;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tonic::{Code, Request};

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

struct Harness {
    svc: AuthzServiceImpl,
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<sid_authn::jwt::JwtService>,
}

async fn harness() -> Harness {
    let backend = PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let jwt = test_jwt();
    let svc = AuthzServiceImpl::new(
        Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
        storage.clone(),
        CedarService::new(),
        Arc::new(AtomicBool::new(false)),
        jwt.clone(),
        Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        )),
        common::RecordingAuditLog::shared(),
    );
    Harness { svc, storage, jwt }
}

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn allow_all(project_id: ProjectId, name: &str) -> CreatePolicyRequest {
    CreatePolicyRequest {
        project_id: project_id.0.to_string(),
        name: name.to_string(),
        policy_text: "permit(principal, action, resource);".to_string(),
        effect: PolicyEffect::Permit as i32,
        enabled: true,
        ..Default::default()
    }
}

/// Regression (#881, K28): without a token nothing is created and no check is
/// answered.
#[tokio::test]
async fn test_authz_rpcs_require_a_token() {
    let h = harness().await;
    let project = ProjectId::new();
    let name = format!("allow-all-{}", uuid::Uuid::now_v7().simple());

    let err = h
        .svc
        .create_policy(Request::new(allow_all(project, &name)))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);

    let err = h
        .svc
        .check_permission(Request::new(about_another(project)))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);

    let err = h
        .svc
        .list_roles(Request::new(ListRolesRequest {
            project_id: project.0.to_string(),
            ..Default::default()
        }))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);

    assert!(
        h.storage
            .list_cedar_policies(project)
            .await
            .unwrap()
            .is_empty(),
        "nothing stored"
    );
}

/// Regression (#881, K28): a signed-in user without the administrator role
/// cannot create policies or roles, assign roles, read the configuration, or
/// ask about another subject.
#[tokio::test]
async fn test_authz_management_refuses_a_non_admin() {
    let h = harness().await;
    let user = Profile::new(Some("mallory"));
    let token = issue_token(&h.jwt, &user, &["openid".to_string()]);
    let project = ProjectId::new();
    let name = format!("allow-all-{}", uuid::Uuid::now_v7().simple());
    let denied = |r: Result<(), tonic::Status>| r.err().map(|e| e.code());

    let results = [
        denied(
            h.svc
                .create_policy(authed(allow_all(project, &name), &token))
                .await
                .map(|_| ()),
        ),
        denied(
            h.svc
                .create_role(authed(
                    CreateRoleRequest {
                        project_id: project.0.to_string(),
                        name: "admin".to_string(),
                        ..Default::default()
                    },
                    &token,
                ))
                .await
                .map(|_| ()),
        ),
        denied(
            h.svc
                .assign_role(authed(
                    authz::AssignRoleRequest {
                        role_id: uuid::Uuid::now_v7().to_string(),
                        principal: Some(authz::assign_role_request::Principal::ProfileId(
                            user.id.to_string(),
                        )),
                        ..Default::default()
                    },
                    &token,
                ))
                .await
                .map(|_| ()),
        ),
        denied(
            h.svc
                .list_policies(authed(
                    ListPoliciesRequest {
                        project_id: project.0.to_string(),
                        ..Default::default()
                    },
                    &token,
                ))
                .await
                .map(|_| ()),
        ),
        denied(
            h.svc
                .list_subjects(authed(
                    ListSubjectsRequest {
                        action: "get".to_string(),
                        resource: "route:/admin".to_string(),
                        ..Default::default()
                    },
                    &token,
                ))
                .await
                .map(|_| ()),
        ),
        denied(
            h.svc
                .check_permission(authed(about_another(project), &token))
                .await
                .map(|_| ()),
        ),
    ];
    for (i, code) in results.into_iter().enumerate() {
        assert_eq!(code, Some(Code::PermissionDenied), "rpc #{i}");
    }
    assert!(
        h.storage
            .list_cedar_policies(project)
            .await
            .unwrap()
            .is_empty(),
        "nothing stored"
    );
}

/// A signed-in user asks about their own subject.
#[tokio::test]
async fn test_authz_check_allows_the_callers_own_subject() {
    let h = harness().await;
    let user = Profile::new(Some("alice"));
    let token = issue_token(&h.jwt, &user, &["openid".to_string()]);
    h.svc
        .check_permission(authed(
            CheckPermissionRequest {
                action: "get".to_string(),
                target: Some(on_project(ProjectId::system())),
                evaluation: Some(authz::check_permission_request::Evaluation::Self_(
                    authz::SelfEvaluation {},
                )),
                ..Default::default()
            },
            &token,
        ))
        .await
        .expect("own subject");
}

/// The whole of `project` as a permission target.
fn on_project(project: ProjectId) -> authz::PermissionTarget {
    authz::PermissionTarget {
        scope: Some(authz::permission_target::Scope::ProjectId(
            project.0.to_string(),
        )),
        object: String::new(),
    }
}

/// A question about a machine user other than the caller, on `project`.
fn about_another(project: ProjectId) -> CheckPermissionRequest {
    CheckPermissionRequest {
        action: "get".to_string(),
        target: Some(on_project(project)),
        evaluation: Some(authz::check_permission_request::Evaluation::NamedSubject(
            authz::SubjectReference {
                kind: Some(authz::subject_reference::Kind::MachineUserId(
                    sid_core::models::MachineUserId::generate().into(),
                )),
            },
        )),
        ..Default::default()
    }
}

/// An administrator manages policies.
#[tokio::test]
async fn test_authz_management_allows_an_administrator() {
    let h = harness().await;
    let token = issue_admin_token(&h.jwt, sid_core::models::ProfileId::generate());
    let name = format!("allow-read-{}", uuid::Uuid::now_v7().simple());
    let created = h
        .svc
        .create_policy(authed(allow_all(ProjectId::system(), &name), &token))
        .await
        .expect("admin creates")
        .into_inner()
        .policy
        .expect("policy");
    h.svc
        .delete_policy(authed(DeletePolicyRequest { id: created.id }, &token))
        .await
        .expect("admin deletes");
}
