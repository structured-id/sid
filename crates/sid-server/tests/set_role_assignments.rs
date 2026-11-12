// SPDX-License-Identifier: AGPL-3.0-only
//! SetRoleAssignments over ListRoleAssignments' set revision, on PostgreSQL
//! (port 54399) and SQLite: a replacement commits only at the revision it
//! was decided on and moves it by one, an empty or unchanged one included,
//! so a change decided earlier never commits after a later one; a retry
//! under its key answers the recorded outcome without moving the revision;
//! the caller's authority covers every managed role, the empty request
//! included; administrative assignments of a managed role stay.

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::{issue_token, test_jwt};
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::cedar::CedarService;
use sid_core::models::{AuditEntry, Profile, ProfileId, ProjectId, Role, RoleAssignmentId};
use sid_infra::grpc_error::extract_error_info;
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz::list_role_assignments_request::Filter;
use sid_proto::sid::v1::authz::role_assignment_set::Holder;
use sid_proto::sid::v1::authz::{
    AdminEnvelope, AdminOperation, AssignRoleRequest, ListRoleAssignmentsRequest, RecipientKind,
    RequestedAssignment, RoleAssignmentSet, SetRoleAssignmentsRequest, SetRoleAssignmentsResponse,
};
use sid_proto::sid::v1::authz_service_server::AuthzService;
use sid_server::grpc::authz_service::AuthzServiceImpl;
use tonic::{Code, Request, Status};

struct Harness {
    svc: Arc<AuthzServiceImpl>,
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<sid_authn::jwt::JwtService>,
    token: String,
}

async fn harness(storage: Arc<dyn StorageBackend>) -> Harness {
    common::adopt_operation_period(storage.as_ref()).await;
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
    let token = common::administrator_token(&jwt, storage.as_ref()).await;
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

fn call<T>(msg: T, token: &str, key: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    common::name_command(req.metadata_mut(), key);
    req
}

fn key() -> String {
    format!("k-{}", uuid::Uuid::now_v7().simple())
}

async fn profile(h: &Harness) -> Profile {
    let profile = Profile::new(Some(format!("p{}", uuid::Uuid::now_v7().simple())));
    h.storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    profile
}

async fn role(h: &Harness) -> Role {
    let ctx = || AuditEntry::system("test", "role").into();
    h.storage.ensure_system_project(ctx()).await.unwrap();
    let tag = uuid::Uuid::now_v7().simple().to_string();
    let mut role = Role::new(ProjectId::SYSTEM, format!("k{tag}"), format!("n{tag}"));
    role.permissions = vec!["ledger.read".into()];
    h.storage.create_role(&role, ctx()).await.unwrap();
    role
}

fn set_of(who: ProfileId) -> RoleAssignmentSet {
    RoleAssignmentSet {
        holder: Some(Holder::ProfileId(who.into())),
        scope: Some("tenant-a".into()),
    }
}

fn days(n: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: (chrono::Utc::now() + chrono::Duration::days(n)).timestamp(),
        nanos: 0,
    }
}

fn set(
    who: ProfileId,
    managed: &[&Role],
    wanted: &[(&Role, Option<i64>)],
    expected: u64,
) -> SetRoleAssignmentsRequest {
    SetRoleAssignmentsRequest {
        assignment_set: Some(set_of(who)),
        managed_role_ids: managed.iter().map(|r| r.id.into()).collect(),
        assignments: wanted
            .iter()
            .map(|(r, until)| RequestedAssignment {
                role_id: Some(r.id.into()),
                expires_at: until.map(days),
            })
            .collect(),
        expected_revision: expected,
    }
}

/// The set's assignments as listed, and its revision.
async fn listed(h: &Harness, who: ProfileId) -> (u64, Vec<RoleAssignmentId>) {
    let listed = h
        .svc
        .list_role_assignments(call(
            ListRoleAssignmentsRequest {
                filter: Some(Filter::AssignmentSet(set_of(who))),
            },
            &h.token,
            &key(),
        ))
        .await
        .unwrap()
        .into_inner();
    (
        listed
            .set_revision
            .expect("a set filter answers its revision"),
        listed
            .assignments
            .into_iter()
            .map(|a| sid_ids_proto::required(a.id.as_ref()).unwrap())
            .collect(),
    )
}

async fn sent(
    h: &Harness,
    request: SetRoleAssignmentsRequest,
    token: &str,
    key: &str,
) -> Result<SetRoleAssignmentsResponse, Status> {
    h.svc
        .set_role_assignments(call(request, token, key))
        .await
        .map(tonic::Response::into_inner)
}

fn ids(response: &SetRoleAssignmentsResponse) -> Vec<RoleAssignmentId> {
    response
        .assignments
        .iter()
        .map(|a| sid_ids_proto::required(a.id.as_ref()).unwrap())
        .collect()
}

/// The refusal of a replacement decided against an older revision.
fn assert_changed(refused: Status, current: u64) {
    assert_eq!(refused.code(), Code::FailedPrecondition, "{refused:?}");
    let (reason, _, metadata) = extract_error_info(&refused).expect("ErrorInfo");
    assert_eq!(reason, "ROLE_ASSIGNMENT_SET_CHANGED");
    assert_eq!(
        metadata.get("currentRevision").map(String::as_str),
        Some(current.to_string().as_str())
    );
}

/// A set read at revision 0 is set to one role: the revision moves to 1 and
/// the list shows exactly the answered assignment; a second request decided
/// on revision 0 is refused and writes nothing.
async fn a_stale_replacement_writes_nothing(h: Harness) {
    let accountant = role(&h).await;
    let who = profile(&h).await.id;
    assert_eq!(listed(&h, who).await, (0, vec![]));

    let first = sent(
        &h,
        set(who, &[&accountant], &[(&accountant, None)], 0),
        &h.token,
        &key(),
    )
    .await
    .unwrap();
    assert_eq!(first.revision, 1);
    assert_eq!(listed(&h, who).await, (1, ids(&first)));

    let refused = sent(&h, set(who, &[&accountant], &[], 0), &h.token, &key())
        .await
        .unwrap_err();
    assert_changed(refused, 1);
    assert_eq!(listed(&h, who).await, (1, ids(&first)), "nothing written");
}

/// A grant decided before an empty replacement that changed nothing never
/// commits after it: the empty one moved the revision.
async fn an_empty_replacement_orders_a_delayed_grant(h: Harness) {
    let accountant = role(&h).await;
    let who = profile(&h).await.id;
    let (decided_on, _) = listed(&h, who).await;
    // A is decided on `decided_on` and delayed; B empties the empty set.
    let b = sent(
        &h,
        set(who, &[&accountant], &[], decided_on),
        &h.token,
        &key(),
    )
    .await
    .unwrap();
    assert_eq!(b.revision, decided_on + 1);
    let a = sent(
        &h,
        set(who, &[&accountant], &[(&accountant, None)], decided_on),
        &h.token,
        &key(),
    )
    .await
    .unwrap_err();
    assert_changed(a, b.revision);
    assert_eq!(listed(&h, who).await, (b.revision, vec![]));
}

/// Back and forth: grant, empty, grant again; each step moves the revision
/// by one, and a request decided on the first state stays refused.
async fn back_and_forth_never_revives_an_old_decision(h: Harness) {
    let accountant = role(&h).await;
    let who = profile(&h).await.id;
    let grant = |expected| set(who, &[&accountant], &[(&accountant, None)], expected);
    let one = sent(&h, grant(0), &h.token, &key()).await.unwrap();
    let two = sent(&h, set(who, &[&accountant], &[], 1), &h.token, &key())
        .await
        .unwrap();
    let three = sent(&h, grant(2), &h.token, &key()).await.unwrap();
    assert_eq!((one.revision, two.revision, three.revision), (1, 2, 3));
    assert_ne!(ids(&one), ids(&three), "a new grant, not the revoked one");
    let old = sent(&h, set(who, &[&accountant], &[], 1), &h.token, &key())
        .await
        .unwrap_err();
    assert_changed(old, 3);
    assert_eq!(listed(&h, who).await, (3, ids(&three)));
}

/// A held assignment of the requested role and end stays; another end
/// replaces it; an unchanged request still moves the revision.
async fn the_same_end_is_kept_another_replaces_it(h: Harness) {
    let accountant = role(&h).await;
    let who = profile(&h).await.id;
    let first = sent(
        &h,
        set(who, &[&accountant], &[(&accountant, Some(10))], 0),
        &h.token,
        &key(),
    )
    .await
    .unwrap();
    let wanted = first.assignments[0].expires_at;
    let unchanged = sent(
        &h,
        SetRoleAssignmentsRequest {
            assignments: vec![RequestedAssignment {
                role_id: Some(accountant.id.into()),
                expires_at: wanted,
            }],
            ..set(who, &[&accountant], &[], 1)
        },
        &h.token,
        &key(),
    )
    .await
    .unwrap();
    assert_eq!(unchanged.revision, 2);
    assert_eq!(ids(&unchanged), ids(&first), "the same end is kept");
    let renewed = sent(
        &h,
        set(who, &[&accountant], &[(&accountant, Some(20))], 2),
        &h.token,
        &key(),
    )
    .await
    .unwrap();
    assert_ne!(ids(&renewed), ids(&first), "another end replaces it");
    assert_eq!(listed(&h, who).await, (3, ids(&renewed)));
}

/// A retry under the same key answers the recorded outcome after a later
/// change, without moving the revision or undoing the later change.
async fn a_retry_answers_the_recorded_outcome(h: Harness) {
    let accountant = role(&h).await;
    let who = profile(&h).await.id;
    let key_a = key();
    let a = sent(
        &h,
        set(who, &[&accountant], &[(&accountant, None)], 0),
        &h.token,
        &key_a,
    )
    .await
    .unwrap();
    let b = sent(&h, set(who, &[&accountant], &[], 1), &h.token, &key())
        .await
        .unwrap();
    let retried = sent(
        &h,
        set(who, &[&accountant], &[(&accountant, None)], 0),
        &h.token,
        &key_a,
    )
    .await
    .expect("the recorded outcome");
    assert_eq!(retried, a);
    assert_eq!(listed(&h, who).await, (b.revision, vec![]), "B stands");
}

/// Two replacements decided on one revision under different keys, sent at
/// once: exactly one commits, the other is refused as stale.
async fn concurrent_replacements_commit_one(h: Harness) {
    let accountant = role(&h).await;
    let who = profile(&h).await.id;
    let (key_left, key_right) = (key(), key());
    let left = sent(
        &h,
        set(who, &[&accountant], &[(&accountant, None)], 0),
        &h.token,
        &key_left,
    );
    let right = sent(&h, set(who, &[&accountant], &[], 0), &h.token, &key_right);
    let (left, right) = tokio::join!(left, right);
    let (won, lost) = match (left, right) {
        (Ok(won), Err(lost)) | (Err(lost), Ok(won)) => (won, lost),
        other => panic!("exactly one commits: {other:?}"),
    };
    assert_changed(lost, 1);
    assert_eq!(listed(&h, who).await, (1, ids(&won)));
}

/// A delegated administrator needs both assignment and revocation of every
/// managed role for the holder, the empty request included; its
/// administrative assignment of a managed role is never touched.
async fn authority_covers_the_whole_request(h: Harness) {
    let accountant = role(&h).await;
    let administrator = role(&h).await;
    let delegate = profile(&h).await;
    let who = profile(&h).await.id;
    let envelope = |operations: &[AdminOperation]| AdminEnvelope {
        operations: operations.iter().map(|o| *o as i32).collect(),
        role_ids: vec![accountant.id.into()],
        permission_ceiling: vec!["ledger.read".into()],
        recipient_kinds: vec![RecipientKind::Profile as i32],
        recipient_group_id: None,
        max_validity: None,
    };
    let grant = |operations: &[AdminOperation]| AssignRoleRequest {
        principal: Some(Principal::ProfileId(delegate.id.into())),
        role_id: Some(administrator.id.into()),
        scope: Some("tenant-a".into()),
        expires_at: None,
        admin: Some(envelope(operations)),
        policy_admin: None,
    };
    let assign_only = h
        .svc
        .assign_role(call(grant(&[AdminOperation::Assign]), &h.token, &key()))
        .await
        .unwrap()
        .into_inner()
        .assignment
        .unwrap();
    let delegate_token = issue_token(&h.jwt, &delegate, &["openid".to_string()]);
    let refused = sent(
        &h,
        set(who, &[&accountant], &[], 0),
        &delegate_token,
        &key(),
    )
    .await
    .unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied, "{refused:?}");
    assert_eq!(listed(&h, who).await.0, 0, "nothing written");

    h.svc
        .assign_role(call(
            grant(&[AdminOperation::Assign, AdminOperation::Revoke]),
            &h.token,
            &key(),
        ))
        .await
        .unwrap();
    let granted = sent(
        &h,
        set(who, &[&accountant], &[(&accountant, None)], 0),
        &delegate_token,
        &key(),
    )
    .await
    .expect("covered");
    assert_eq!(granted.revision, 1);

    // The delegate's own set holds administrative assignments of the
    // administrator role; managing that role leaves them in place.
    let own = SetRoleAssignmentsRequest {
        assignment_set: Some(set_of(delegate.id)),
        managed_role_ids: vec![administrator.id.into()],
        assignments: vec![],
        expected_revision: listed(&h, delegate.id).await.0,
    };
    sent(&h, own, &h.token, &key())
        .await
        .expect("the root manages it");
    let kept = h
        .storage
        .get_role_assignment(sid_ids_proto::required(assign_only.id.as_ref()).unwrap())
        .await
        .unwrap();
    assert!(
        kept.is_some(),
        "an administrative assignment is never touched"
    );
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
    a_stale_replacement_writes_nothing,
    an_empty_replacement_orders_a_delayed_grant,
    back_and_forth_never_revives_an_old_decision,
    the_same_end_is_kept_another_replaces_it,
    a_retry_answers_the_recorded_outcome,
    concurrent_replacements_commit_one,
    authority_covers_the_whole_request,
);
