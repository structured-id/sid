// SPDX-License-Identifier: AGPL-3.0-only
//! AuthzService refusals: each carries the reason a client switches on, a
//! policy is stored only when Cedar can parse it, and role assignments are
//! listed by role.
//!
//! Requires sid-test-postgres on port 54399.

mod common;

use common::{error_reason, issue_admin_token, test_jwt};
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::models::{AuditEntry, Profile, ProfileId, Project, ProjectId};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz_service_server::AuthzService;
use sid_proto::sid::v1::*;
use sid_storage::PostgresBackend;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tonic::{Code, Request, Status};

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// The service, and a project of its own so one test's policies never reach
/// another's evaluation.
struct Harness {
    svc: AuthzServiceImpl,
    storage: Arc<dyn StorageBackend>,
    token: String,
    project: ProjectId,
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
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = AuthzServiceImpl::new(
        Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
        storage.clone(),
        CedarService::new(),
        Arc::new(AtomicBool::new(false)),
        jwt,
        Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        )),
        common::RecordingAuditLog::shared(),
    );
    let project = Project::new(unique("authz-errors"), None);
    storage
        .create_project(&project, AuditEntry::system("test", "setup").into())
        .await
        .expect("project");
    Harness {
        svc,
        storage,
        token,
        project: project.id,
    }
}

impl Harness {
    /// A stored profile, so an assignment to it satisfies the profile reference.
    async fn profile(&self) -> ProfileId {
        let profile = Profile::new(None::<String>);
        self.storage
            .create_profile(&profile, AuditEntry::system("test", "setup").into())
            .await
            .expect("profile");
        profile.id
    }

    fn policy(&self, name: &str, text: &str) -> CreatePolicyRequest {
        CreatePolicyRequest {
            project_id: self.project.0.to_string(),
            name: name.to_string(),
            policy_text: text.to_string(),
            effect: PolicyEffect::Permit as i32,
            enabled: true,
            ..Default::default()
        }
    }

    fn authed<T>(&self, msg: T) -> Request<T> {
        let mut req = Request::new(msg);
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.token).parse().unwrap(),
        );
        req
    }
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::now_v7().simple())
}

/// The field a BadRequest refusal names.
fn violated_field(status: &Status) -> Option<String> {
    tonic_types::StatusExt::get_details_bad_request(status)
        .and_then(|b| b.field_violations.into_iter().next())
        .map(|v| v.field)
}

const VALID: &str = "permit(principal, action, resource);";
const UNPARSEABLE: &str = "permit(principal, action";

/// Regression: a policy Cedar cannot parse was stored, and the engine then
/// refused every Cedar permit of the project without saying why. It is
/// refused when it is created and nothing is stored.
#[tokio::test]
async fn test_create_policy_refuses_text_cedar_cannot_parse() {
    let h = harness().await;
    let name = unique("broken");
    let err = h
        .svc
        .create_policy(h.authed(h.policy(&name, UNPARSEABLE)))
        .await
        .expect_err("unparseable policy");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(error_reason(&err).as_deref(), Some("INVALID_FIELD_VALUE"));
    assert_eq!(violated_field(&err).as_deref(), Some("policy_text"));
    let stored = h.storage.list_cedar_policies(h.project).await.unwrap();
    assert!(stored.is_empty(), "nothing stored");
}

/// Regression: an update could replace a working policy with text Cedar
/// cannot parse. It is refused and the stored text stays.
#[tokio::test]
async fn test_update_policy_refuses_text_cedar_cannot_parse() {
    let h = harness().await;
    let created = h
        .svc
        .create_policy(h.authed(h.policy(&unique("working"), VALID)))
        .await
        .expect("valid policy")
        .into_inner()
        .policy
        .expect("policy");
    let err = h
        .svc
        .update_policy(h.authed(UpdatePolicyRequest {
            id: created.id.clone(),
            policy_text: Some(UNPARSEABLE.to_string()),
            ..Default::default()
        }))
        .await
        .expect_err("unparseable policy");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(violated_field(&err).as_deref(), Some("policy_text"));
    let stored = h
        .svc
        .get_policy(h.authed(GetPolicyRequest { id: created.id }))
        .await
        .expect("stored")
        .into_inner()
        .policy
        .expect("policy");
    assert_eq!(stored.policy_text, VALID);
}

/// A second policy of the same name in a project is POLICY_ALREADY_EXISTS.
#[tokio::test]
async fn test_duplicate_policy_name_is_policy_already_exists() {
    let h = harness().await;
    let name = unique("dup");
    h.svc
        .create_policy(h.authed(h.policy(&name, VALID)))
        .await
        .expect("first");
    let err = h
        .svc
        .create_policy(h.authed(h.policy(&name, VALID)))
        .await
        .expect_err("second");
    assert_eq!(err.code(), Code::AlreadyExists);
    assert_eq!(error_reason(&err).as_deref(), Some("POLICY_ALREADY_EXISTS"));
}

/// A second group of the same name in a project is GROUP_ALREADY_EXISTS.
#[tokio::test]
async fn test_duplicate_group_name_is_group_already_exists() {
    let h = harness().await;
    let name = unique("dup-group");
    let group = || authz::CreateGroupRequest {
        project_id: h.project.0.to_string(),
        name: name.clone(),
        ..Default::default()
    };
    h.svc.create_group(h.authed(group())).await.expect("first");
    let err = h
        .svc
        .create_group(h.authed(group()))
        .await
        .expect_err("second");
    assert_eq!(err.code(), Code::AlreadyExists);
    assert_eq!(error_reason(&err).as_deref(), Some("GROUP_ALREADY_EXISTS"));
}

/// Unknown role, group and policy identifiers each name their resource type.
#[tokio::test]
async fn test_unknown_identifiers_are_typed_not_found() {
    let h = harness().await;
    let missing = uuid::Uuid::now_v7().to_string();

    let err = h
        .svc
        .get_role(h.authed(authz::GetRoleRequest {
            identifier: Some(authz::get_role_request::Identifier::Id(missing.clone())),
            ..Default::default()
        }))
        .await
        .expect_err("no role");
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(error_reason(&err).as_deref(), Some("ROLE_NOT_FOUND"));

    let err = h
        .svc
        .get_group(h.authed(authz::GetGroupRequest {
            identifier: Some(authz::get_group_request::Identifier::Id(missing.clone())),
            ..Default::default()
        }))
        .await
        .expect_err("no group");
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(error_reason(&err).as_deref(), Some("GROUP_NOT_FOUND"));

    let err = h
        .svc
        .get_policy(h.authed(GetPolicyRequest { id: missing }))
        .await
        .expect_err("no policy");
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(error_reason(&err).as_deref(), Some("POLICY_NOT_FOUND"));
}

/// Regression: listing assignments by role was refused as unimplemented. It
/// returns every assignment of that role and no other.
#[tokio::test]
async fn test_list_role_assignments_by_role() {
    let h = harness().await;
    let project = h.project.0.to_string();
    let create_role = |name: String| authz::CreateRoleRequest {
        project_id: project.clone(),
        name,
        ..Default::default()
    };
    let role = h
        .svc
        .create_role(h.authed(create_role(unique("listed"))))
        .await
        .expect("role")
        .into_inner()
        .role
        .expect("role");
    let other = h
        .svc
        .create_role(h.authed(create_role(unique("other"))))
        .await
        .expect("role")
        .into_inner()
        .role
        .expect("role");
    let assign = |role_id: &str, profile: ProfileId| authz::AssignRoleRequest {
        role_id: role_id.to_string(),
        principal: Some(authz::assign_role_request::Principal::ProfileId(
            profile.to_string(),
        )),
        ..Default::default()
    };
    let mut expected = Vec::new();
    for _ in 0..2 {
        let a = h
            .svc
            .assign_role(h.authed(assign(&role.id, h.profile().await)))
            .await
            .expect("assign")
            .into_inner()
            .assignment
            .expect("assignment");
        expected.push(a.id);
    }
    h.svc
        .assign_role(h.authed(assign(&other.id, h.profile().await)))
        .await
        .expect("assign other");

    let listed = h
        .svc
        .list_role_assignments(h.authed(authz::ListRoleAssignmentsRequest {
            filter: Some(authz::list_role_assignments_request::Filter::RoleId(
                role.id.clone(),
            )),
        }))
        .await
        .expect("listed by role")
        .into_inner()
        .assignments;
    let mut ids: Vec<String> = listed.into_iter().map(|a| a.id).collect();
    ids.sort();
    expected.sort();
    assert_eq!(ids, expected);
}

/// Regression: a subject Cedar cannot read as an entity was answered as an
/// internal error. It is INVALID_ARGUMENT naming the subject field.
#[tokio::test]
async fn test_evaluate_policy_names_an_unreadable_subject() {
    let h = harness().await;
    h.svc
        .create_policy(h.authed(h.policy(&unique("eval"), VALID)))
        .await
        .expect("policy");
    let err = h
        .svc
        .evaluate_policy(h.authed(EvaluatePolicyRequest {
            project_id: Some(h.project.0.to_string()),
            subject: "alice\"".to_string(),
            action: "read".to_string(),
            resource: "doc".to_string(),
            ..Default::default()
        }))
        .await
        .expect_err("unreadable subject");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(violated_field(&err).as_deref(), Some("subject"));
}
