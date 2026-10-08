// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of PatService's administration RPCs against real PostgreSQL
//! (port 54399). Listing every user's personal access tokens and revoking any
//! of them is instance administration; without this, anyone could enumerate
//! every token and revoke the tokens of other users.

mod common;

use common::test_jwt;
use sid_core::models::{AuditEntry, PersonalAccessToken, ProfileId, profile::Profile};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::pat_service_server::PatService;
use sid_proto::sid::v1::{AdminRevokePatRequest, ListAllPatsRequest};
use sid_server::grpc::pat_service::PatServiceImpl;
use std::sync::Arc;
use tonic::{Code, Request};
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn pg_storage() -> Arc<dyn StorageBackend> {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");
    Arc::new(backend)
}

/// A stored profile with `roles`.
async fn profile(storage: &Arc<dyn StorageBackend>, roles: &[&str]) -> Profile {
    let id = ProfileId::generate();
    let mut profile = Profile::new(Some(format!("pat-{id}")));
    profile.id = id;
    profile.roles = roles.iter().map(|r| r.to_string()).collect();
    storage
        .create_profile(&profile, AuditEntry::system("test.setup", "pat").into())
        .await
        .unwrap();
    profile
}

/// A stored active token of `owner`.
async fn pat(storage: &Arc<dyn StorageBackend>, owner: ProfileId) -> PersonalAccessToken {
    let id = Uuid::now_v7().simple().to_string();
    let pat = PersonalAccessToken::new(
        owner,
        "ci",
        format!("hash-{id}"),
        format!("sid_pat_{}", &id[..8]),
        vec!["repos:read".into()],
    );
    storage
        .create_pat(&pat, None, AuditEntry::system("test.setup", "pat").into())
        .await
        .unwrap();
    pat
}

fn req<T>(msg: T, token: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    if let Some(token) = token {
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    req
}

async fn service(
    storage: Arc<dyn StorageBackend>,
) -> (PatServiceImpl, Arc<sid_authn::jwt::JwtService>) {
    let jwt = test_jwt();
    let svc = PatServiceImpl::new(storage, jwt.clone(), common::test_revocation());
    (svc, jwt)
}

/// Regression (#881): without a token no one lists every token or revokes
/// another user's token, and the token stays active.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pat_admin_rpcs_require_a_token() {
    let storage = pg_storage().await;
    let owner = profile(&storage, &[]).await;
    let victim = pat(&storage, owner.id).await;
    let (svc, _) = service(storage.clone()).await;

    let listed = svc.list_all_pats(req(ListAllPatsRequest {}, None)).await;
    assert_eq!(listed.err().map(|e| e.code()), Some(Code::Unauthenticated));
    let revoked = svc
        .admin_revoke_pat(req(
            AdminRevokePatRequest {
                pat_id: victim.id.0.to_string(),
            },
            None,
        ))
        .await;
    assert_eq!(revoked.err().map(|e| e.code()), Some(Code::Unauthenticated));
    let stored = storage.get_pat(victim.id).await.unwrap().unwrap();
    assert!(stored.is_usable(), "the token must stay active");
}

/// Regression (#881): a signed-in user without the administrator role, the
/// token's own owner included, cannot use the administration RPCs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pat_admin_rpcs_refuse_a_non_admin() {
    let storage = pg_storage().await;
    let owner = profile(&storage, &[]).await;
    let victim = pat(&storage, owner.id).await;
    let (svc, jwt) = service(storage.clone()).await;
    let token = common::issue_token(&jwt, &owner, &["openid".to_string()]);

    let listed = svc
        .list_all_pats(req(ListAllPatsRequest {}, Some(&token)))
        .await;
    assert_eq!(listed.err().map(|e| e.code()), Some(Code::PermissionDenied));
    let revoked = svc
        .admin_revoke_pat(req(
            AdminRevokePatRequest {
                pat_id: victim.id.0.to_string(),
            },
            Some(&token),
        ))
        .await;
    assert_eq!(
        revoked.err().map(|e| e.code()),
        Some(Code::PermissionDenied)
    );
    assert!(
        storage
            .get_pat(victim.id)
            .await
            .unwrap()
            .unwrap()
            .is_usable()
    );
}

/// An administrator revokes another user's token, and the token records that
/// administrator as the one who revoked it, not a placeholder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_admin_revocation_records_the_administrator() {
    let storage = pg_storage().await;
    let owner = profile(&storage, &[]).await;
    let admin = profile(&storage, &["admin"]).await;
    let victim = pat(&storage, owner.id).await;
    let (svc, jwt) = service(storage.clone()).await;
    let token = common::issue_token(&jwt, &admin, &["openid".to_string()]);

    svc.admin_revoke_pat(req(
        AdminRevokePatRequest {
            pat_id: victim.id.0.to_string(),
        },
        Some(&token),
    ))
    .await
    .expect("admin revokes");
    let stored = storage.get_pat(victim.id).await.unwrap().unwrap();
    assert!(!stored.is_usable());
    assert_eq!(
        stored.revoked_by.as_deref(),
        Some(admin.id.to_string().as_str())
    );
}

/// A user at the active-token limit is refused with QUOTA_EXCEEDED and a
/// QuotaFailure naming the limit: a count limit, not a rate limit, so
/// waiting does not lift it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_beyond_the_token_limit_is_quota_exceeded() {
    use sid_core::models::pat::PAT_MAX_ACTIVE_PER_USER;
    use tonic_types::StatusExt;

    let storage = pg_storage().await;
    let owner = profile(&storage, &[]).await;
    for _ in 0..PAT_MAX_ACTIVE_PER_USER {
        pat(&storage, owner.id).await;
    }
    let (svc, jwt) = service(storage.clone()).await;
    let token = common::issue_token(&jwt, &owner, &["openid".to_string()]);

    let refused = svc
        .create_pat(req(
            sid_proto::sid::v1::CreatePatRequest {
                name: "one more".into(),
                scopes: vec!["repos:read".into()],
                expires_at: Some(prost_types::Timestamp {
                    seconds: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp(),
                    nanos: 0,
                }),
                ..Default::default()
            },
            Some(&token),
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::ResourceExhausted);
    let details = refused.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "QUOTA_EXCEEDED");
    assert_eq!(
        details.quota_failure().unwrap().violations[0].subject,
        "personal_access_tokens"
    );
}

/// A personal access token bound to no registered resource is inadmissible:
/// exchanging it issues no token and records no use, since the token it
/// would yield names no resource any verifier may accept it for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exchange_of_an_unbound_token_issues_nothing() {
    let storage = pg_storage().await;
    let owner = profile(&storage, &[]).await;
    let (svc, jwt) = service(storage.clone()).await;
    let token = common::issue_token(&jwt, &owner, &["openid".to_string()]);
    let created = svc
        .create_pat(req(
            sid_proto::sid::v1::CreatePatRequest {
                name: "ci".into(),
                scopes: vec!["repos:read".into()],
                expires_at: Some(prost_types::Timestamp {
                    seconds: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp(),
                    nanos: 0,
                }),
                ..Default::default()
            },
            Some(&token),
        ))
        .await
        .expect("create")
        .into_inner();

    let refused = svc
        .exchange_pat(req(
            sid_proto::sid::v1::ExchangePatRequest {
                token: created.token,
                scope: String::new(),
            },
            None,
        ))
        .await
        .expect_err("an unbound PAT");
    assert_eq!(refused.code(), Code::FailedPrecondition);
    let pat_id = sid_core::models::PatId(Uuid::parse_str(&created.pat_id).unwrap());
    let stored = storage.get_pat(pat_id).await.unwrap().unwrap();
    assert_eq!(stored.use_count, 0, "no use recorded");
}

/// Revoking a token that does not exist is not reported as done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_admin_revocation_of_an_unknown_token_is_not_found() {
    let storage = pg_storage().await;
    let admin = profile(&storage, &["admin"]).await;
    let (svc, jwt) = service(storage.clone()).await;
    let token = common::issue_token(&jwt, &admin, &["openid".to_string()]);

    let revoked = svc
        .admin_revoke_pat(req(
            AdminRevokePatRequest {
                pat_id: Uuid::now_v7().to_string(),
            },
            Some(&token),
        ))
        .await;
    assert_eq!(revoked.err().map(|e| e.code()), Some(Code::NotFound));
}
