// SPDX-License-Identifier: AGPL-3.0-only
//! AssignRole as a keyed command, on PostgreSQL (port 54399) and SQLite: a
//! repeated operation key returns the assignment the first call made and
//! makes none, even after that assignment was revoked; the same key with
//! another request conflicts; concurrent calls with one key make one
//! assignment; keys are per caller.

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::{issue_admin_token, test_jwt};
use sid_authn::operation::OPERATION_KEY_HEADER;
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::grpc_error::extract_error_info;
use sid_core::models::{AuditEntry, Profile, ProfileId, ProjectId, Role};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz::list_role_assignments_request::Filter;
use sid_proto::sid::v1::authz::{AssignRoleRequest, ListRoleAssignmentsRequest, RevokeRoleRequest};
use sid_proto::sid::v1::authz_service_server::AuthzService;
use tonic::{Code, Request};

struct Harness {
    svc: Arc<AuthzServiceImpl>,
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<sid_authn::jwt::JwtService>,
    token: String,
}

async fn harness(storage: Arc<dyn StorageBackend>) -> Harness {
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
    let token = issue_admin_token(&jwt, ProfileId::generate());
    Harness {
        svc: Arc::new(svc),
        storage,
        jwt,
        token,
    }
}

async fn postgres() -> Harness {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into());
    let backend = sid_storage::PostgresBackend::new(&url, None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    harness(Arc::new(backend)).await
}

async fn sqlite() -> Harness {
    harness(Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    ))
    .await
}

fn call<T>(msg: T, token: &str, key: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    if let Some(key) = key {
        req.metadata_mut()
            .insert(OPERATION_KEY_HEADER, key.parse().unwrap());
    }
    req
}

fn tag() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

async fn profile(h: &Harness) -> ProfileId {
    let profile = Profile::new(Some(format!("p{}", tag())));
    h.storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    profile.id
}

async fn role(h: &Harness) -> Role {
    let ctx = || AuditEntry::system("test", "role").into();
    h.storage.ensure_system_project(ctx()).await.unwrap();
    let tag = tag();
    let mut role = Role::new(ProjectId::system(), format!("k{tag}"), format!("n{tag}"));
    role.permissions = vec!["ledger.read".into()];
    h.storage.create_role(&role, ctx()).await.unwrap();
    role
}

fn assign(role: &Role, to: ProfileId) -> AssignRoleRequest {
    AssignRoleRequest {
        principal: Some(Principal::ProfileId(to.to_string())),
        role_id: role.id.0.to_string(),
        scope: None,
        expires_at: None,
        admin: None,
        policy_admin: None,
    }
}

async fn assigned(h: &Harness, request: AssignRoleRequest, key: &str) -> String {
    h.svc
        .assign_role(call(request, &h.token, Some(key)))
        .await
        .expect("assigned")
        .into_inner()
        .assignment
        .expect("assignment")
        .id
}

async fn held(h: &Harness, who: ProfileId) -> Vec<String> {
    h.svc
        .list_role_assignments(call(
            ListRoleAssignmentsRequest {
                filter: Some(Filter::ProfileId(who.to_string())),
            },
            &h.token,
            None,
        ))
        .await
        .unwrap()
        .into_inner()
        .assignments
        .into_iter()
        .map(|a| a.id)
        .collect()
}

/// A repeated key returns the assignment the first call made, and only one
/// exists.
async fn repeated_key_returns_the_first_assignment(h: Harness) {
    let role = role(&h).await;
    let who = profile(&h).await;
    let key = format!("k-{}", tag());
    let first = assigned(&h, assign(&role, who), &key).await;
    let again = assigned(&h, assign(&role, who), &key).await;
    assert_eq!(again, first);
    assert_eq!(held(&h, who).await, vec![first]);
}

/// A retry after the assignment was revoked gets the recorded assignment
/// and recreates nothing: a revoked authority is not restored by a retry.
async fn retry_after_revocation_recreates_nothing(h: Harness) {
    let role = role(&h).await;
    let who = profile(&h).await;
    let key = format!("k-{}", tag());
    let first = assigned(&h, assign(&role, who), &key).await;
    h.svc
        .revoke_role(call(
            RevokeRoleRequest {
                assignment_id: first.clone(),
            },
            &h.token,
            None,
        ))
        .await
        .unwrap();
    let retried = assigned(&h, assign(&role, who), &key).await;
    assert_eq!(retried, first, "the recorded answer");
    assert!(held(&h, who).await.is_empty(), "nothing recreated");
}

/// The same key with another request is refused and assigns nothing.
async fn the_same_key_for_another_request_conflicts(h: Harness) {
    let role = role(&h).await;
    let who = profile(&h).await;
    let other = profile(&h).await;
    let key = format!("k-{}", tag());
    assigned(&h, assign(&role, who), &key).await;
    let refused = h
        .svc
        .assign_role(call(assign(&role, other), &h.token, Some(&key)))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::AlreadyExists);
    assert_eq!(
        extract_error_info(&refused).expect("ErrorInfo").0,
        "OPERATION_KEY_CONFLICT"
    );
    assert!(held(&h, other).await.is_empty());
}

/// Concurrent calls with one key make one assignment and all answer it.
async fn concurrent_calls_with_one_key_assign_once(h: Harness) {
    let role = role(&h).await;
    let who = profile(&h).await;
    let key = format!("k-{}", tag());
    let calls = (0..4).map(|_| {
        let svc = h.svc.clone();
        let request = call(assign(&role, who), &h.token, Some(&key));
        async move { svc.assign_role(request).await }
    });
    let ids: Vec<String> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| r.expect("assigned").into_inner().assignment.unwrap().id)
        .collect();
    let stored = held(&h, who).await;
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert!(ids.iter().all(|id| *id == stored[0]), "{ids:?}");
}

/// Keys belong to the caller: another administrator's call under the same
/// key is its own command.
async fn keys_are_per_caller(h: Harness) {
    let role = role(&h).await;
    let who = profile(&h).await;
    let other = profile(&h).await;
    let key = format!("k-{}", tag());
    let mine = assigned(&h, assign(&role, who), &key).await;
    let theirs = h
        .svc
        .assign_role(call(
            assign(&role, other),
            &issue_admin_token(&h.jwt, ProfileId::generate()),
            Some(&key),
        ))
        .await
        .expect("another caller's command")
        .into_inner()
        .assignment
        .unwrap()
        .id;
    assert_ne!(mine, theirs);
}

/// Without a key a call is as before: each one assigns.
async fn without_a_key_each_call_assigns(h: Harness) {
    let role = role(&h).await;
    let who = profile(&h).await;
    for _ in 0..2 {
        h.svc
            .assign_role(call(assign(&role, who), &h.token, None))
            .await
            .unwrap();
    }
    assert_eq!(held(&h, who).await.len(), 2);
}

macro_rules! on_both_engines {
    ($($scenario:ident),* $(,)?) => {
        mod pg {
            $(
                #[tokio::test]
                async fn $scenario() {
                    super::$scenario(super::postgres().await).await;
                }
            )*
        }
        mod lite {
            $(
                #[tokio::test]
                async fn $scenario() {
                    super::$scenario(super::sqlite().await).await;
                }
            )*
        }
    };
}

on_both_engines!(
    repeated_key_returns_the_first_assignment,
    retry_after_revocation_recreates_nothing,
    the_same_key_for_another_request_conflicts,
    concurrent_calls_with_one_key_assign_once,
    keys_are_per_caller,
    without_a_key_each_call_assigns,
);
