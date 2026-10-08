// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of GovernanceService: a user files access requests only for
//! themselves, and only an administrator lists, approves or denies requests and
//! grants temporary roles.

mod common;

use common::mock_storage::MockStorage;
use common::{issue_admin_token, issue_token, test_jwt, test_revocation};
use sid_authz::governance_grpc::GovernanceServiceImpl;
use sid_core::models::Profile;
use sid_proto::sid::v1::authz::governance_service_server::GovernanceService;
use sid_proto::sid::v1::authz::{
    AccessRequestMessage, DecideRequestRequest, GrantTemporaryRoleRequest,
    ListPendingRequestsRequest,
};
use std::sync::Arc;
use tonic::{Code, Request};

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn service(storage: MockStorage) -> GovernanceServiceImpl {
    GovernanceServiceImpl::new(Arc::new(storage), test_jwt(), test_revocation())
}

fn in_one_day() -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp(),
        nanos: 0,
    }
}

/// Regression:without a token nobody files requests, reads the pending
/// queue or grants a temporary role.
#[tokio::test]
async fn test_governance_rpcs_require_a_token() {
    let victim = Profile::new(Some("alice"));
    let svc = service(MockStorage::new().with_profile(victim.clone()));

    let err = svc
        .request_access(Request::new(AccessRequestMessage {
            requester_profile_id: victim.id.to_string(),
            requested_role: "admin".to_string(),
            ..Default::default()
        }))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);

    let err = svc
        .list_pending_requests(Request::new(ListPendingRequestsRequest::default()))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);

    let err = svc
        .grant_temporary_role(Request::new(GrantTemporaryRoleRequest {
            profile_id: victim.id.to_string(),
            role: "admin".to_string(),
            expires_at: Some(in_one_day()),
            ..Default::default()
        }))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// Regression:a signed-in user cannot file a request in someone else's
/// name, read the queue, approve requests or grant roles.
#[tokio::test]
async fn test_governance_rpcs_refuse_a_non_admin() {
    let victim = Profile::new(Some("alice"));
    let user = Profile::new(Some("mallory"));
    let svc = service(
        MockStorage::new()
            .with_profile(victim.clone())
            .with_profile(user.clone()),
    );
    let token = issue_token(&test_jwt(), &user, &["openid".to_string()]);

    let err = svc
        .request_access(authed(
            AccessRequestMessage {
                requester_profile_id: victim.id.to_string(),
                requested_role: "admin".to_string(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .expect_err("foreign requester");
    assert_eq!(err.code(), Code::PermissionDenied);

    let err = svc
        .list_pending_requests(authed(ListPendingRequestsRequest::default(), &token))
        .await
        .expect_err("not an administrator");
    assert_eq!(err.code(), Code::PermissionDenied);

    let err = svc
        .decide_request(authed(
            DecideRequestRequest {
                request_id: uuid::Uuid::now_v7().to_string(),
                approved: true,
                reason: String::new(),
            },
            &token,
        ))
        .await
        .expect_err("not an administrator");
    assert_eq!(err.code(), Code::PermissionDenied);

    let err = svc
        .grant_temporary_role(authed(
            GrantTemporaryRoleRequest {
                profile_id: user.id.to_string(),
                role: "admin".to_string(),
                expires_at: Some(in_one_day()),
                ..Default::default()
            },
            &token,
        ))
        .await
        .expect_err("not an administrator");
    assert_eq!(err.code(), Code::PermissionDenied);
}

/// The queue fails when a requester cannot be read, instead of listing the
/// request under the raw profile id as if the requester were gone.
#[tokio::test]
async fn test_pending_queue_with_unreadable_requester_is_reported() {
    let admin = Profile::new(Some("root"));
    let user = Profile::new(Some("alice"));
    let storage = Arc::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(admin.clone())
            .with_profile(user.clone()),
    );
    use sid_plugin::StorageBackend;
    storage
        .create_role(
            &sid_core::models::Role::new(sid_core::models::ProjectId::system(), "viewer", "Viewer"),
            sid_core::models::AuditEntry::system("test", "role").into(),
        )
        .await
        .unwrap();
    let svc = GovernanceServiceImpl::new(storage.clone(), test_jwt(), test_revocation());
    let user_token = issue_token(&test_jwt(), &user, &["openid".to_string()]);
    svc.request_access(authed(
        AccessRequestMessage {
            requester_profile_id: user.id.to_string(),
            requested_role: "viewer".to_string(),
            project_id: sid_core::models::ProjectId::system().0.to_string(),
            ..Default::default()
        },
        &user_token,
    ))
    .await
    .expect("request filed");

    storage.fail_profile_reads();
    let err = svc
        .list_pending_requests(authed(
            ListPendingRequestsRequest::default(),
            &issue_admin_token(&test_jwt(), admin.id),
        ))
        .await
        .expect_err("a queue was listed without its requesters");
    assert_eq!(err.code(), Code::Internal);
}

/// An administrator reads the queue; a decision on an unknown request is
/// NOT_FOUND, not a permission error.
#[tokio::test]
async fn test_governance_rpcs_allow_an_administrator() {
    let admin = Profile::new(Some("root"));
    let svc = service(MockStorage::new().with_profile(admin.clone()));
    let token = issue_admin_token(&test_jwt(), admin.id);

    svc.list_pending_requests(authed(ListPendingRequestsRequest::default(), &token))
        .await
        .expect("admin lists");
    let err = svc
        .decide_request(authed(
            DecideRequestRequest {
                request_id: uuid::Uuid::now_v7().to_string(),
                approved: true,
                reason: String::new(),
            },
            &token,
        ))
        .await
        .expect_err("unknown request");
    assert_eq!(err.code(), Code::NotFound);
}
