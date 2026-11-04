// SPDX-License-Identifier: AGPL-3.0-only
//! The authorization administration commands as keyed commands, on
//! PostgreSQL (port 54399) and SQLite: a repeated operation key returns the
//! assignment the first call made and makes none, even after that assignment
//! was revoked; the same key with another request conflicts; concurrent calls
//! with one key make one assignment; keys are per caller; a call without a
//! key is refused; retried role creation and membership removal answer as
//! their first call and undo no later change.

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::test_jwt;
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::grpc_error::extract_error_info;
use sid_core::models::{AuditEntry, Profile, ProfileId, ProjectId, Role};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz::list_role_assignments_request::Filter;
use sid_proto::sid::v1::authz::{
    AddToGroupRequest, AssignRoleRequest, CreateGroupRequest, CreateRoleRequest,
    ListRoleAssignmentsRequest, RemoveFromGroupRequest, RevokeRoleRequest,
};
use sid_proto::sid::v1::authz_service_server::AuthzService;
use tonic::{Code, Request};

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

fn call<T>(msg: T, token: &str, key: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    if let Some(key) = key {
        common::name_command(req.metadata_mut(), key);
    }
    req
}

fn tag() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

/// The unique part of a key made as `k-{tag}`.
fn tag_of(key: &str) -> &str {
    key.trim_start_matches("k-")
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
            Some(&format!("k-{}", tag())),
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
            &common::administrator_token(&h.jwt, h.storage.as_ref()).await,
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

/// A call without a key cannot promise a safe retry: it is refused and
/// assigns nothing.
async fn without_a_key_nothing_is_assigned(h: Harness) {
    let role = role(&h).await;
    let who = profile(&h).await;
    let refused = h
        .svc
        .assign_role(call(assign(&role, who), &h.token, None))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument);
    assert_eq!(
        extract_error_info(&refused).expect("ErrorInfo").0,
        "REQUIRED_FIELD_MISSING"
    );
    assert!(held(&h, who).await.is_empty());
}

/// A role creation is retried after its response was lost: the retry
/// answers with the role it created, not "name taken" by that very role.
async fn role_creation_retry_answers_with_its_role(h: Harness) {
    h.storage
        .ensure_system_project(AuditEntry::system("test", "role").into())
        .await
        .unwrap();
    let key = format!("k-{}", tag());
    let create = || {
        call(
            CreateRoleRequest {
                project_id: ProjectId::system().0.to_string(),
                name: format!("n{}", tag_of(&key)),
                description: None,
                permissions: vec!["ledger.read".into()],
            },
            &h.token,
            Some(&key),
        )
    };
    let first = h.svc.create_role(create()).await.unwrap().into_inner();
    let retry = h
        .svc
        .create_role(create())
        .await
        .expect("the retry answers with the role it created")
        .into_inner();
    assert_eq!(retry, first);
}

/// A member's removal is retried after the member was added back: the retry
/// answers as the first removal and leaves the later addition in place.
async fn membership_removal_retry_keeps_a_later_addition(h: Harness) {
    h.storage
        .ensure_system_project(AuditEntry::system("test", "group").into())
        .await
        .unwrap();
    let who = profile(&h).await;
    let group = h
        .svc
        .create_group(call(
            CreateGroupRequest {
                project_id: ProjectId::system().0.to_string(),
                name: format!("g{}", tag()),
                description: None,
            },
            &h.token,
            Some(&format!("k-{}", tag())),
        ))
        .await
        .unwrap()
        .into_inner()
        .group
        .unwrap()
        .id;
    let add = || {
        call(
            AddToGroupRequest {
                group_id: group.clone(),
                profile_id: who.to_string(),
            },
            &h.token,
            Some(&format!("k-{}", tag())),
        )
    };
    let key = format!("k-{}", tag());
    let remove = || {
        call(
            RemoveFromGroupRequest {
                group_id: group.clone(),
                profile_id: who.to_string(),
            },
            &h.token,
            Some(&key),
        )
    };
    h.svc.add_to_group(add()).await.unwrap();
    h.svc.remove_from_group(remove()).await.unwrap();
    h.svc.add_to_group(add()).await.unwrap();
    h.svc.remove_from_group(remove()).await.unwrap();

    let members = h
        .storage
        .list_group_members(sid_core::models::GroupId(
            uuid::Uuid::parse_str(&group).unwrap(),
        ))
        .await
        .unwrap();
    assert!(
        members.iter().any(|m| m.profile_id == who),
        "the retried removal took the later addition away"
    );
}

/// Concurrent attempts of one group creation: the losers meet the group's
/// unique name before the key, and still answer with the group the winner
/// created, not "name taken" by it.
async fn concurrent_group_creations_with_one_key_answer_one_group(h: Harness) {
    h.storage
        .ensure_system_project(AuditEntry::system("test", "group").into())
        .await
        .unwrap();
    let key = format!("k-{}", tag());
    let name = format!("g{}", tag_of(&key));
    let calls = (0..4).map(|_| {
        let svc = h.svc.clone();
        let request = call(
            CreateGroupRequest {
                project_id: ProjectId::system().0.to_string(),
                name: name.clone(),
                description: None,
            },
            &h.token,
            Some(&key),
        );
        async move { svc.create_group(request).await }
    });
    let ids: std::collections::BTreeSet<String> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| {
            r.expect("every attempt answers")
                .into_inner()
                .group
                .unwrap()
                .id
        })
        .collect();
    assert_eq!(ids.len(), 1, "{ids:?}");
}

/// An edit that names no description changes nothing and is still its
/// command's outcome: retried after a later edit it answers as it did.
async fn group_edit_without_a_description_is_recorded(h: Harness) {
    use sid_proto::sid::v1::authz::UpdateGroupRequest;
    h.storage
        .ensure_system_project(AuditEntry::system("test", "group").into())
        .await
        .unwrap();
    let group = h
        .svc
        .create_group(call(
            CreateGroupRequest {
                project_id: ProjectId::system().0.to_string(),
                name: format!("g{}", tag()),
                description: Some("first".into()),
            },
            &h.token,
            Some(&format!("k-{}", tag())),
        ))
        .await
        .unwrap()
        .into_inner()
        .group
        .unwrap()
        .id;
    let edit = |description: Option<&str>, key: &str| {
        call(
            UpdateGroupRequest {
                id: group.clone(),
                description: description.map(str::to_owned),
            },
            &h.token,
            Some(key),
        )
    };
    let key = format!("k-{}", tag());
    let first = h
        .svc
        .update_group(edit(None, &key))
        .await
        .unwrap()
        .into_inner();
    h.svc
        .update_group(edit(Some("later"), &format!("k-{}", tag())))
        .await
        .unwrap();
    let retried = h
        .svc
        .update_group(edit(None, &key))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(retried, first, "the retry answers as the first attempt");
}

/// A description edit answers with the group as its commit left it, as a
/// read of the group shows it afterwards and as its retry repeats it; never
/// a group composed before the write, whose name or time the store did not
/// keep.
async fn group_edit_answers_the_group_its_commit_left(h: Harness) {
    use sid_proto::sid::v1::authz::{GetGroupRequest, UpdateGroupRequest, get_group_request};
    h.storage
        .ensure_system_project(AuditEntry::system("test", "group").into())
        .await
        .unwrap();
    let group = h
        .svc
        .create_group(call(
            CreateGroupRequest {
                project_id: ProjectId::system().0.to_string(),
                name: format!("g{}", tag()),
                description: Some("first".into()),
            },
            &h.token,
            Some(&format!("k-{}", tag())),
        ))
        .await
        .unwrap()
        .into_inner()
        .group
        .unwrap()
        .id;
    let key = format!("k-{}", tag());
    let edit = || {
        call(
            UpdateGroupRequest {
                id: group.clone(),
                description: Some("second".into()),
            },
            &h.token,
            Some(&key),
        )
    };
    let answered = h.svc.update_group(edit()).await.unwrap().into_inner().group;
    let stored = h
        .svc
        .get_group(call(
            GetGroupRequest {
                project_id: Some(ProjectId::system().0.to_string()),
                identifier: Some(get_group_request::Identifier::Id(group.clone())),
            },
            &h.token,
            None,
        ))
        .await
        .unwrap()
        .into_inner()
        .group;
    assert_eq!(answered, stored);
    let retried = h.svc.update_group(edit()).await.unwrap().into_inner().group;
    assert_eq!(retried, answered);
}

/// A policy edit answers with the revision its commit stored, as a read of
/// the policy shows it and as its retry repeats it.
async fn policy_edit_answers_its_stored_revision(h: Harness) {
    use sid_proto::sid::v1::authz::{CreatePolicyRequest, GetPolicyRequest, UpdatePolicyRequest};
    h.storage
        .ensure_system_project(AuditEntry::system("test", "policy").into())
        .await
        .unwrap();
    let created = h
        .svc
        .create_policy(call(
            CreatePolicyRequest {
                scope: Some(sid_proto::sid::v1::PolicyScope {
                    scope: Some(sid_proto::sid::v1::policy_scope::Scope::ProjectId(
                        ProjectId::system().0.to_string(),
                    )),
                }),
                name: format!("p{}", tag()),
                policy_text: "permit(principal, action, resource);".into(),
                effect: sid_proto::sid::v1::PolicyEffect::Permit as i32,
                enabled: true,
                ..Default::default()
            },
            &h.token,
            Some(&format!("k-{}", tag())),
        ))
        .await
        .unwrap()
        .into_inner()
        .policy
        .unwrap();
    let key = format!("k-{}", tag());
    let edit = || {
        call(
            UpdatePolicyRequest {
                id: created.id.clone(),
                description: Some("edited".into()),
                ..Default::default()
            },
            &h.token,
            Some(&key),
        )
    };
    let edited = h
        .svc
        .update_policy(edit())
        .await
        .unwrap()
        .into_inner()
        .policy
        .unwrap();
    let stored = h
        .svc
        .get_policy(call(
            GetPolicyRequest {
                id: created.id.clone(),
            },
            &h.token,
            None,
        ))
        .await
        .unwrap()
        .into_inner()
        .policy
        .unwrap();
    assert_eq!(
        edited.revision, stored.revision,
        "the answer shows the stored revision"
    );
    assert_eq!(edited.revision, created.revision + 1);
    let retried = h
        .svc
        .update_policy(edit())
        .await
        .unwrap()
        .into_inner()
        .policy
        .unwrap();
    assert_eq!(retried, edited);
}

/// The policy every concurrent-edit scenario edits.
async fn policy(h: &Harness) -> sid_proto::sid::v1::Policy {
    use sid_proto::sid::v1::authz::CreatePolicyRequest;
    h.storage
        .ensure_system_project(AuditEntry::system("test", "policy").into())
        .await
        .unwrap();
    h.svc
        .create_policy(call(
            CreatePolicyRequest {
                scope: Some(sid_proto::sid::v1::PolicyScope {
                    scope: Some(sid_proto::sid::v1::policy_scope::Scope::ProjectId(
                        ProjectId::system().0.to_string(),
                    )),
                }),
                name: format!("p{}", tag()),
                policy_text: "permit(principal, action, resource);".into(),
                effect: sid_proto::sid::v1::PolicyEffect::Permit as i32,
                enabled: true,
                ..Default::default()
            },
            &h.token,
            Some(&format!("k-{}", tag())),
        ))
        .await
        .unwrap()
        .into_inner()
        .policy
        .unwrap()
}

/// Regression guard: concurrent attempts of one policy edit read the same
/// revision; the losers' revision-conditional writes find it moved on by
/// the winner, and still answer with the winner's recorded edit rather than
/// "changed concurrently".
async fn concurrent_policy_edits_with_one_key_answer_one_edit(h: Harness) {
    use sid_proto::sid::v1::authz::UpdatePolicyRequest;
    let created = policy(&h).await;
    let key = format!("k-{}", tag());
    let calls = (0..4).map(|_| {
        let svc = h.svc.clone();
        let request = call(
            UpdatePolicyRequest {
                id: created.id.clone(),
                description: Some("edited".into()),
                ..Default::default()
            },
            &h.token,
            Some(&key),
        );
        async move { svc.update_policy(request).await }
    });
    let answers: Vec<_> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| r.expect("every attempt answers").into_inner())
        .collect();
    assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");
    assert_eq!(
        answers[0].policy.as_ref().unwrap().revision,
        created.revision + 1,
        "one edit was made"
    );
}

/// Regression guard: concurrent attempts of one role edit all answer with
/// the edit the winner recorded.
async fn concurrent_role_edits_with_one_key_answer_one_edit(h: Harness) {
    use sid_proto::sid::v1::authz::UpdateRoleRequest;
    let role = role(&h).await;
    let key = format!("k-{}", tag());
    let calls = (0..4).map(|_| {
        let svc = h.svc.clone();
        let request = call(
            UpdateRoleRequest {
                id: role.id.0.to_string(),
                description: Some("edited".into()),
                ..Default::default()
            },
            &h.token,
            Some(&key),
        );
        async move { svc.update_role(request).await }
    });
    let answers: Vec<_> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| r.expect("every attempt answers").into_inner())
        .collect();
    assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");
}

/// Regression guard: concurrent attempts of one policy deletion answer as
/// the deletion, though the losers find the policy the winner deleted gone.
async fn concurrent_policy_deletions_with_one_key_answer_one_deletion(h: Harness) {
    use sid_proto::sid::v1::authz::DeletePolicyRequest;
    let created = policy(&h).await;
    let key = format!("k-{}", tag());
    let calls = (0..4).map(|_| {
        let svc = h.svc.clone();
        let request = call(
            DeletePolicyRequest {
                id: created.id.clone(),
            },
            &h.token,
            Some(&key),
        );
        async move { svc.delete_policy(request).await }
    });
    for answer in futures::future::join_all(calls).await {
        answer.expect("every attempt answers as the deletion");
    }
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
    without_a_key_nothing_is_assigned,
    role_creation_retry_answers_with_its_role,
    membership_removal_retry_keeps_a_later_addition,
    concurrent_group_creations_with_one_key_answer_one_group,
    group_edit_without_a_description_is_recorded,
    group_edit_answers_the_group_its_commit_left,
    policy_edit_answers_its_stored_revision,
    concurrent_policy_edits_with_one_key_answer_one_edit,
    concurrent_role_edits_with_one_key_answer_one_edit,
    concurrent_policy_deletions_with_one_key_answer_one_deletion,
);
