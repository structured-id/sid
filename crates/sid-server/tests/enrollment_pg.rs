// SPDX-License-Identifier: AGPL-3.0-only
//! Enrollment service PostgreSQL integration tests.
//!
//! Tests invite CRUD lifecycle through EnrollmentServiceImpl
//! with real PostgreSQL storage (port 54399).

mod common;

use common::test_jwt;
use sid_core::models::AuditEntry;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;
use std::sync::Arc;
use tonic::Request;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn setup_pg_storage() -> Arc<dyn StorageBackend> {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");
    Arc::new(backend)
}

/// Create a profile + issue admin token. Returns (service, bearer token).
async fn setup_service_with_auth(
    storage: Arc<dyn StorageBackend>,
) -> (
    sid_server::grpc::enrollment_service::EnrollmentServiceImpl,
    String,
) {
    let (svc, bearer, _) = setup_named(storage).await;
    (svc, bearer)
}

/// [`setup_service_with_auth`], with the administrator's username, which
/// the invites it creates record as their creator's name.
async fn setup_named(
    storage: Arc<dyn StorageBackend>,
) -> (
    sid_server::grpc::enrollment_service::EnrollmentServiceImpl,
    String,
    String,
) {
    let jwt = test_jwt();
    let profile_id = sid_core::models::ProfileId::generate();
    let username = format!("enroll-{profile_id}");
    let mut profile = sid_core::models::profile::Profile::new(Some(username.clone()));
    profile.id = profile_id;
    profile.roles = vec!["admin".into()];
    storage
        .create_profile(
            &profile,
            AuditEntry::system("test.setup", "enrollment").into(),
        )
        .await
        .unwrap();

    let bearer = common::issue_token(&jwt, &profile, &["openid".to_string()]);
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        storage,
        jwt,
        common::test_revocation(),
    );
    (svc, bearer, username)
}

fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_enrollment_create_list_revoke_lifecycle() {
    let storage = setup_pg_storage().await;
    let (svc, bearer) = setup_service_with_auth(storage).await;

    // Create invite
    let create_req = authed_request(
        sid_proto::sid::v1::admin::CreateInviteRequest {
            max_uses: 3,
            metadata: Default::default(),
            expires_at: None,
        },
        &bearer,
    );
    let invite = svc.create_invite(create_req).await.unwrap().into_inner();
    assert!(!invite.code.is_empty());
    assert_eq!(invite.max_uses, 3);
    assert!(invite.active);

    // List — should contain our invite
    let list_req = authed_request(
        sid_proto::sid::v1::admin::ListInvitesRequest {
            status: 0,
            page_size: 100,
            page_token: String::new(),
            search: String::new(),
        },
        &bearer,
    );
    let list_resp = svc.list_invites(list_req).await.unwrap().into_inner();
    assert!(
        list_resp.invites.iter().any(|i| i.code == invite.code),
        "created invite should appear in list"
    );

    // Revoke
    let revoke_req = authed_request(
        sid_proto::sid::v1::admin::RevokeInviteRequest {
            invite_id: invite.id.clone(),
        },
        &bearer,
    );
    svc.revoke_invite(revoke_req).await.unwrap();

    // List active — revoked should NOT appear
    let active_req = authed_request(
        sid_proto::sid::v1::admin::ListInvitesRequest {
            status: sid_proto::sid::v1::admin::InviteStatus::Active as i32,
            page_size: 100,
            page_token: String::new(),
            search: String::new(),
        },
        &bearer,
    );
    let active_resp = svc.list_invites(active_req).await.unwrap().into_inner();
    assert!(
        !active_resp.invites.iter().any(|i| i.code == invite.code),
        "revoked invite should not appear in active list"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_enrollment_bulk_create_persists() {
    let storage = setup_pg_storage().await;
    let (svc, bearer) = setup_service_with_auth(storage).await;

    let req = authed_request(
        sid_proto::sid::v1::admin::BulkCreateInvitesRequest {
            count: 3,
            max_uses: 2,
            metadata: Default::default(),
            expires_at: None,
        },
        &bearer,
    );
    let bulk_resp = svc.bulk_create_invites(req).await.unwrap().into_inner();
    assert_eq!(bulk_resp.invites.len(), 3);

    // All 3 should appear in list
    let list_req = authed_request(
        sid_proto::sid::v1::admin::ListInvitesRequest {
            status: 0,
            page_size: 100,
            page_token: String::new(),
            search: String::new(),
        },
        &bearer,
    );
    let list_resp = svc.list_invites(list_req).await.unwrap().into_inner();
    for inv in &bulk_resp.invites {
        assert!(
            list_resp.invites.iter().any(|i| i.code == inv.code),
            "bulk-created invite {} should appear in list",
            inv.code
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_enrollment_registration_stats() {
    let storage = setup_pg_storage().await;
    let (svc, bearer) = setup_service_with_auth(storage).await;

    let req = authed_request(
        sid_proto::sid::v1::admin::GetRegistrationStatsRequest { period_days: 30 },
        &bearer,
    );
    // Every storage query the statistics need runs against PostgreSQL.
    svc.get_registration_stats(req).await.unwrap();
}

/// Regression:without a token nobody reads the invite codes (which
/// would defeat invite-only registration), revokes an invite or reads the
/// registration statistics.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_enrollment_rpcs_require_a_token() {
    let storage = setup_pg_storage().await;
    let (svc, bearer) = setup_service_with_auth(storage).await;
    let invite = svc
        .create_invite(authed_request(
            sid_proto::sid::v1::admin::CreateInviteRequest {
                max_uses: 1,
                metadata: Default::default(),
                expires_at: None,
            },
            &bearer,
        ))
        .await
        .unwrap()
        .into_inner();

    let err = svc
        .list_invites(Request::new(
            sid_proto::sid::v1::admin::ListInvitesRequest {
                status: 0,
                page_size: 100,
                page_token: String::new(),
                search: String::new(),
            },
        ))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let err = svc
        .revoke_invite(Request::new(
            sid_proto::sid::v1::admin::RevokeInviteRequest {
                invite_id: invite.id.clone(),
            },
        ))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let err = svc
        .get_registration_stats(Request::new(
            sid_proto::sid::v1::admin::GetRegistrationStatsRequest { period_days: 30 },
        ))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// The invites of this test's administrator: the search matches the
/// creator's name, which is the administrator's username.
fn own_invites(
    svc_admin: &str,
    page_token: String,
) -> sid_proto::sid::v1::admin::ListInvitesRequest {
    sid_proto::sid::v1::admin::ListInvitesRequest {
        status: 0,
        page_size: 2,
        page_token,
        search: svc_admin.to_string(),
    }
}

/// Regression: the page token was ignored, so every page was the first and
/// the rest of the invites could not be reached. Following the tokens sees
/// each invite once, and the last page has none. The search scopes the
/// listing to the invites this administrator created.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_enrollment_list_pages_through_every_invite() {
    let storage = setup_pg_storage().await;
    let (svc, bearer, name) = setup_named(storage).await;
    let created = svc
        .bulk_create_invites(authed_request(
            sid_proto::sid::v1::admin::BulkCreateInvitesRequest {
                count: 5,
                max_uses: 1,
                metadata: Default::default(),
                expires_at: None,
            },
            &bearer,
        ))
        .await
        .unwrap()
        .into_inner()
        .invites;

    let mut seen = Vec::new();
    let mut token = String::new();
    loop {
        let page = svc
            .list_invites(authed_request(own_invites(&name, token), &bearer))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total_count, 5);
        seen.extend(page.invites.into_iter().map(|i| i.id));
        if page.next_page_token.is_empty() {
            break;
        }
        token = page.next_page_token;
    }
    seen.sort();
    let mut expected: Vec<_> = created.into_iter().map(|i| i.id).collect();
    expected.sort();
    assert_eq!(seen, expected);
}

/// Regression: an expiry that is not a valid timestamp became "now" and a
/// past one was accepted, so the invite was born expired; a bulk request for
/// more than the limit was quietly cut. Each is refused naming its field,
/// and nothing is created.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_enrollment_refuses_values_it_would_replace() {
    let storage = setup_pg_storage().await;
    let (svc, bearer, name) = setup_named(storage).await;
    let before = svc
        .list_invites(authed_request(own_invites(&name, String::new()), &bearer))
        .await
        .unwrap()
        .into_inner()
        .total_count;

    let past = prost_types::Timestamp {
        seconds: chrono::Utc::now().timestamp() - 60,
        nanos: 0,
    };
    let unreadable = prost_types::Timestamp {
        seconds: 0,
        nanos: -1,
    };
    for expires_at in [past, unreadable] {
        let err = svc
            .create_invite(authed_request(
                sid_proto::sid::v1::admin::CreateInviteRequest {
                    max_uses: 1,
                    metadata: Default::default(),
                    expires_at: Some(expires_at),
                },
                &bearer,
            ))
            .await
            .expect_err("not a future timestamp");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(violated_field(&err).as_deref(), Some("expires_at"));
    }

    let err = svc
        .bulk_create_invites(authed_request(
            sid_proto::sid::v1::admin::BulkCreateInvitesRequest {
                count: 101,
                max_uses: 1,
                metadata: Default::default(),
                expires_at: None,
            },
            &bearer,
        ))
        .await
        .expect_err("over the bulk limit");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(violated_field(&err).as_deref(), Some("count"));

    let after = svc
        .list_invites(authed_request(own_invites(&name, String::new()), &bearer))
        .await
        .unwrap()
        .into_inner()
        .total_count;
    assert_eq!(after, before, "a refused request created invites");
}

/// An undefined status filter, a foreign page token and an unknown invite
/// are refused with their reason; a statistics period beyond the
/// representable time is refused instead of overflowing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_enrollment_refusals_carry_their_reason() {
    let storage = setup_pg_storage().await;
    let (svc, bearer) = setup_service_with_auth(storage).await;

    let err = svc
        .list_invites(authed_request(
            sid_proto::sid::v1::admin::ListInvitesRequest {
                status: 99,
                ..own_invites("", String::new())
            },
            &bearer,
        ))
        .await
        .expect_err("undefined status");
    assert_eq!(violated_field(&err).as_deref(), Some("status"));

    let err = svc
        .list_invites(authed_request(
            own_invites("", "not-a-token".into()),
            &bearer,
        ))
        .await
        .expect_err("foreign token");
    assert_eq!(violated_field(&err).as_deref(), Some("page_token"));

    let err = svc
        .revoke_invite(authed_request(
            sid_proto::sid::v1::admin::RevokeInviteRequest {
                invite_id: uuid::Uuid::now_v7().to_string(),
            },
            &bearer,
        ))
        .await
        .expect_err("unknown invite");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        common::error_reason(&err).as_deref(),
        Some("INVITE_NOT_FOUND")
    );

    let err = svc
        .get_registration_stats(authed_request(
            sid_proto::sid::v1::admin::GetRegistrationStatsRequest {
                period_days: u32::MAX,
            },
            &bearer,
        ))
        .await
        .expect_err("a period before representable time");
    assert_eq!(violated_field(&err).as_deref(), Some("period_days"));
}

/// The field a BadRequest refusal names.
fn violated_field(status: &tonic::Status) -> Option<String> {
    tonic_types::StatusExt::get_details_bad_request(status)
        .and_then(|b| b.field_violations.into_iter().next())
        .map(|v| v.field)
}

/// Regression:a signed-in user without the administrator role
/// cannot create, list or revoke invites.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_enrollment_rpcs_refuse_a_non_admin() {
    let storage = setup_pg_storage().await;
    let (svc, _admin) = setup_service_with_auth(storage).await;
    let user = sid_core::models::profile::Profile::new(Some("mallory"));
    let token = common::issue_token(&test_jwt(), &user, &["openid".to_string()]);

    let err = svc
        .create_invite(authed_request(
            sid_proto::sid::v1::admin::CreateInviteRequest {
                max_uses: 0,
                metadata: Default::default(),
                expires_at: None,
            },
            &token,
        ))
        .await
        .expect_err("not an administrator");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = svc
        .bulk_create_invites(authed_request(
            sid_proto::sid::v1::admin::BulkCreateInvitesRequest {
                count: 5,
                max_uses: 1,
                metadata: Default::default(),
                expires_at: None,
            },
            &token,
        ))
        .await
        .expect_err("not an administrator");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = svc
        .list_invites(authed_request(
            sid_proto::sid::v1::admin::ListInvitesRequest {
                status: 0,
                page_size: 100,
                page_token: String::new(),
                search: String::new(),
            },
            &token,
        ))
        .await
        .expect_err("not an administrator");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
