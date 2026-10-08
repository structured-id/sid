// SPDX-License-Identifier: AGPL-3.0-only
//! What governance grants: an approved access request gives the requester the
//! requested role of the named project, together with the approval or not at
//! all, and a temporary role is that project role with an expiry. A request
//! for a role the project does not define is refused when filed.

mod common;

use std::sync::Arc;

use common::mock_storage::MockStorage;
use common::{error_reason, issue_admin_token, issue_token, test_jwt, test_revocation};
use sid_authz::governance_grpc::GovernanceServiceImpl;
use sid_core::models::{
    AccessRequestId, AccessRequestStatus, AssignmentProvenance, AuditEntry, Profile, ProjectId,
    Role, RoleAssignmentPrincipal,
};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz::governance_service_server::GovernanceService;
use sid_proto::sid::v1::authz::{
    AccessRequestMessage, DecideRequestRequest, GrantTemporaryRoleRequest,
};
use tonic::{Code, Request};

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

struct Setup {
    svc: GovernanceServiceImpl,
    storage: Arc<MockStorage>,
    admin: Profile,
    user: Profile,
    admin_token: String,
    user_token: String,
    role: Role,
}

/// The system project with a `viewer` role, a user and an administrator.
async fn setup() -> Setup {
    let admin = Profile::new(Some("root"));
    let user = Profile::new(Some("alice"));
    let storage = Arc::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(admin.clone())
            .with_profile(user.clone()),
    );
    let role = Role::new(ProjectId::system(), "viewer", "Viewer");
    storage
        .create_role(&role, AuditEntry::system("test", "role").into())
        .await
        .unwrap();
    Setup {
        svc: GovernanceServiceImpl::new(storage.clone(), test_jwt(), test_revocation()),
        storage,
        admin_token: issue_admin_token(&test_jwt(), admin.id),
        user_token: issue_token(&test_jwt(), &user, &["openid".to_string()]),
        admin,
        user,
        role,
    }
}

/// The administrator granted it as root of its scope, on no basis.
fn granted_by_root(s: &Setup) -> Option<AssignmentProvenance> {
    Some(AssignmentProvenance {
        granted_by: format!("user:{}", s.admin.id),
        basis: None,
        depends_on: None,
        ceiling: None,
    })
}

fn request_for(s: &Setup, role: &str, hours: Option<i64>) -> AccessRequestMessage {
    AccessRequestMessage {
        requester_profile_id: s.user.id.to_string(),
        requested_role: role.to_string(),
        justification: "on call".into(),
        requested_duration: hours.map(|h| prost_types::Duration {
            seconds: h * 3600,
            nanos: 0,
        }),
        project_id: ProjectId::system().0.to_string(),
    }
}

async fn file(s: &Setup, role: &str, hours: Option<i64>) -> String {
    s.svc
        .request_access(authed(request_for(s, role, hours), &s.user_token))
        .await
        .expect("request filed")
        .into_inner()
        .request_id
}

fn approve(s: &Setup, request_id: &str) -> Request<DecideRequestRequest> {
    authed(
        DecideRequestRequest {
            request_id: request_id.to_string(),
            approved: true,
            reason: String::new(),
        },
        &s.admin_token,
    )
}

/// Approval assigns the requested role itself to the requester, for the
/// requested time, with no scope standing in for the role.
#[tokio::test]
async fn approval_assigns_the_requested_role() {
    let s = setup().await;
    let id = file(&s, "viewer", Some(8)).await;
    s.svc
        .decide_request(approve(&s, &id))
        .await
        .expect("approved");

    let assigned = s
        .storage
        .list_role_assignments_for_profile(s.user.id)
        .await
        .unwrap();
    assert_eq!(assigned.len(), 1);
    assert_eq!(assigned[0].role_id, s.role.id);
    assert_eq!(
        assigned[0].principal,
        RoleAssignmentPrincipal::Profile(s.user.id)
    );
    assert_eq!(assigned[0].scope, None);
    assert_eq!(assigned[0].provenance, granted_by_root(&s));
    let expiry = assigned[0].expires_at.expect("a timed request expires");
    let hours = (expiry - chrono::Utc::now()).num_minutes();
    assert!((7 * 60..=8 * 60).contains(&hours), "{hours} minutes left");
}

/// A role the project does not define, or an unknown project, is refused
/// when the request is filed; nothing is stored.
#[tokio::test]
async fn a_request_names_an_existing_project_role() {
    let s = setup().await;
    let err = s
        .svc
        .request_access(authed(request_for(&s, "nonexistent", None), &s.user_token))
        .await
        .expect_err("unknown role");
    assert_eq!(err.code(), Code::NotFound, "{err:?}");
    assert_eq!(error_reason(&err).as_deref(), Some("ROLE_NOT_FOUND"));

    let mut elsewhere = request_for(&s, "viewer", None);
    elsewhere.project_id = ProjectId::new().0.to_string();
    let err = s
        .svc
        .request_access(authed(elsewhere, &s.user_token))
        .await
        .expect_err("unknown project");
    assert_eq!(err.code(), Code::NotFound, "{err:?}");
    assert_eq!(error_reason(&err).as_deref(), Some("PROJECT_NOT_FOUND"));
    assert!(
        s.storage
            .list_pending_access_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

/// A role deleted before approval cannot be granted: the approval fails and
/// the request stays pending, with no role assigned.
#[tokio::test]
async fn an_approval_that_cannot_grant_records_nothing() {
    let s = setup().await;
    let id = file(&s, "viewer", None).await;
    s.storage
        .delete_role(s.role.id, AuditEntry::system("test", "role").into())
        .await
        .unwrap();

    let err = s
        .svc
        .decide_request(approve(&s, &id))
        .await
        .expect_err("the role is gone");
    assert_eq!(err.code(), Code::FailedPrecondition, "{err:?}");
    assert_eq!(error_reason(&err).as_deref(), Some("INVALID_STATE"));
    let stored = s
        .storage
        .get_access_request(AccessRequestId(uuid::Uuid::parse_str(&id).unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, AccessRequestStatus::Pending);
    assert!(
        s.storage
            .list_role_assignments_for_profile(s.user.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A temporary role is the project role, assigned until its expiry; an
/// unknown role is NOT_FOUND.
#[tokio::test]
async fn a_temporary_role_is_the_project_role() {
    let s = setup().await;
    let expires = chrono::Utc::now() + chrono::Duration::days(1);
    let grant = |role: &str| {
        authed(
            GrantTemporaryRoleRequest {
                profile_id: s.user.id.to_string(),
                role: role.to_string(),
                expires_at: Some(prost_types::Timestamp {
                    seconds: expires.timestamp(),
                    nanos: 0,
                }),
                justification: "incident".into(),
                project_id: ProjectId::system().0.to_string(),
            },
            &s.admin_token,
        )
    };
    let err = s
        .svc
        .grant_temporary_role(grant("nonexistent"))
        .await
        .expect_err("unknown role");
    assert_eq!(err.code(), Code::NotFound, "{err:?}");

    s.svc
        .grant_temporary_role(grant("viewer"))
        .await
        .expect("granted");
    let assigned = s
        .storage
        .list_role_assignments_for_profile(s.user.id)
        .await
        .unwrap();
    assert_eq!(assigned.len(), 1);
    assert_eq!(assigned[0].role_id, s.role.id);
    assert_eq!(assigned[0].scope, None);
    assert_eq!(assigned[0].provenance, granted_by_root(&s));
    assert_eq!(
        assigned[0].expires_at.map(|t| t.timestamp()),
        Some(expires.timestamp())
    );
}

/// Regression: a negative or zero requested duration was turned into one
/// hour. It is refused, naming the field, and nothing is filed.
#[tokio::test]
async fn a_duration_that_is_not_positive_is_refused() {
    let s = setup().await;
    for hours in [-5, 0] {
        let err = s
            .svc
            .request_access(authed(
                request_for(&s, "viewer", Some(hours)),
                &s.user_token,
            ))
            .await
            .expect_err("not a positive duration");
        assert_eq!(err.code(), Code::InvalidArgument, "{hours}: {err:?}");
        assert_eq!(error_reason(&err).as_deref(), Some("INVALID_FIELD_VALUE"));
    }
    assert!(
        s.storage
            .list_pending_access_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

/// An unknown request is ACCESS_REQUEST_NOT_FOUND; a request decided once is
/// INVALID_STATE on the second decision, which grants nothing more.
#[tokio::test]
async fn decisions_name_unknown_and_decided_requests() {
    let s = setup().await;
    let err = s
        .svc
        .decide_request(approve(&s, &uuid::Uuid::now_v7().to_string()))
        .await
        .expect_err("unknown request");
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(
        error_reason(&err).as_deref(),
        Some("ACCESS_REQUEST_NOT_FOUND")
    );

    let id = file(&s, "viewer", None).await;
    s.svc
        .decide_request(approve(&s, &id))
        .await
        .expect("approved");
    let err = s
        .svc
        .decide_request(approve(&s, &id))
        .await
        .expect_err("decided twice");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(error_reason(&err).as_deref(), Some("INVALID_STATE"));
    assert_eq!(
        s.storage
            .list_role_assignments_for_profile(s.user.id)
            .await
            .unwrap()
            .len(),
        1
    );
}
