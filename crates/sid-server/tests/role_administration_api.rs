// SPDX-License-Identifier: AGPL-3.0-only
//! Constrained role administration (D050 B) through AssignRole: the
//! administrator grants an administrative envelope, its holder, who is no
//! administrator, assigns within it, and both records carry their envelope
//! and provenance. A malformed envelope is refused naming its field.
//!
//! Requires sid-test-postgres on port 54399.

mod common;

use common::{issue_admin_token, issue_token, test_jwt};
use sid_authn::revocation_cache::RevocationCache;
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::models::{AuditEntry, Profile, ProfileId, ProjectId, Role};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz::list_role_assignments_request::Filter;
use sid_proto::sid::v1::authz::{
    AdminEnvelope, AdminOperation, AssignRoleRequest, ListRoleAssignmentsRequest, RecipientKind,
    RoleAssignment,
};
use sid_proto::sid::v1::authz_service_server::AuthzService;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tonic::{Code, Request};

struct Harness {
    svc: AuthzServiceImpl,
    storage: Arc<dyn StorageBackend>,
    admin: ProfileId,
    admin_token: String,
}

async fn harness() -> Harness {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string());
    let backend = sid_storage::PostgresBackend::new(&url, None)
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
    let admin = ProfileId::generate();
    Harness {
        svc,
        storage,
        admin,
        admin_token: issue_admin_token(&jwt, admin),
    }
}

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

async fn stored_profile(h: &Harness) -> Profile {
    let profile = Profile::new(Some(format!("p{}", uuid::Uuid::now_v7().simple())));
    h.storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    profile
}

async fn stored_role(h: &Harness, permissions: &[&str]) -> Role {
    let ctx = || AuditEntry::system("test", "role").into();
    h.storage.ensure_system_project(ctx()).await.unwrap();
    let tag = uuid::Uuid::now_v7().simple().to_string();
    let mut role = Role::new(ProjectId::system(), format!("k{tag}"), format!("n{tag}"));
    role.permissions = permissions.iter().map(|p| p.to_string()).collect();
    h.storage.create_role(&role, ctx()).await.unwrap();
    role
}

fn days(n: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: (chrono::Utc::now() + chrono::Duration::days(n)).timestamp(),
        nanos: 0,
    }
}

fn assign(role: &Role, to: ProfileId, expires: Option<i64>) -> AssignRoleRequest {
    AssignRoleRequest {
        principal: Some(Principal::ProfileId(to.to_string())),
        role_id: role.id.0.to_string(),
        scope: None,
        expires_at: expires.map(days),
        admin: None,
    }
}

/// Assign `role` to Profiles, within 30 days, for roles holding at most
/// `ledger.post` and `ledger.read` (in the sorted order the envelope is
/// returned in).
fn accountant_envelope(role: &Role) -> AdminEnvelope {
    AdminEnvelope {
        operations: vec![AdminOperation::Assign as i32],
        role_ids: vec![role.id.0.to_string()],
        permission_ceiling: vec!["ledger.post".into(), "ledger.read".into()],
        recipient_kinds: vec![RecipientKind::Profile as i32],
        recipient_group_id: None,
        max_validity: Some(prost_types::Duration {
            seconds: 30 * 86_400,
            nanos: 0,
        }),
    }
}

async fn granted(h: &Harness, request: AssignRoleRequest, token: &str) -> RoleAssignment {
    h.svc
        .assign_role(authed(request, token))
        .await
        .expect("assigned")
        .into_inner()
        .assignment
        .expect("assignment")
}

/// The administrator grants an envelope; its holder assigns the working
/// role it covers, only with an expiry, and never the administrative role
/// itself; each record shows who granted it on what authority.
#[tokio::test]
async fn an_envelope_holder_assigns_within_it() {
    let h = harness().await;
    let accountant = stored_role(&h, &["ledger.read", "ledger.post"]).await;
    let administrator_role = stored_role(&h, &["roles.administer"]).await;
    let access_admin = stored_profile(&h).await;
    let worker = stored_profile(&h).await;

    let mut grant = assign(&administrator_role, access_admin.id, None);
    grant.admin = Some(accountant_envelope(&accountant));
    let admin_grant = granted(&h, grant, &h.admin_token).await;
    assert_eq!(admin_grant.admin, Some(accountant_envelope(&accountant)));
    let provenance = admin_grant.provenance.clone().expect("provenance");
    assert_eq!(provenance.granted_by, format!("user:{}", h.admin));
    assert_eq!(provenance.basis_assignment_id, None);
    assert_eq!(provenance.depends_on_assignment_id, None);

    let holder_token = issue_token(&test_jwt(), &access_admin, &["openid".to_string()]);
    let err = h
        .svc
        .assign_role(authed(assign(&accountant, worker.id, None), &holder_token))
        .await
        .expect_err("an administered assignment expires");
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
    let err = h
        .svc
        .assign_role(authed(
            assign(&administrator_role, worker.id, Some(1)),
            &holder_token,
        ))
        .await
        .expect_err("the envelope covers only the accountant role");
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");

    let working = granted(&h, assign(&accountant, worker.id, Some(10)), &holder_token).await;
    assert_eq!(working.admin, None);
    let provenance = working.provenance.expect("provenance");
    assert_eq!(provenance.granted_by, format!("user:{}", access_admin.id));
    assert_eq!(provenance.basis_assignment_id, Some(admin_grant.id.clone()));
    assert_eq!(provenance.depends_on_assignment_id, None);

    let listed = h
        .svc
        .list_role_assignments(authed(
            ListRoleAssignmentsRequest {
                filter: Some(Filter::ProfileId(access_admin.id.to_string())),
            },
            &h.admin_token,
        ))
        .await
        .unwrap()
        .into_inner()
        .assignments;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].admin, Some(accountant_envelope(&accountant)));
}

/// UpdateRole never widens a role past the ceiling an envelope approved one
/// of its assignments under: the administrator is told which precondition
/// fails, and the assignment shows the ceiling that binds it.
#[tokio::test]
async fn update_role_keeps_approved_ceilings() {
    use sid_proto::sid::v1::authz::UpdateRoleRequest;
    let h = harness().await;
    let accountant = stored_role(&h, &["ledger.read", "ledger.post"]).await;
    let administrator_role = stored_role(&h, &["roles.administer"]).await;
    let access_admin = stored_profile(&h).await;
    let worker = stored_profile(&h).await;
    let mut grant = assign(&administrator_role, access_admin.id, None);
    grant.admin = Some(accountant_envelope(&accountant));
    granted(&h, grant, &h.admin_token).await;
    let holder_token = issue_token(&test_jwt(), &access_admin, &["openid".to_string()]);
    let working = granted(&h, assign(&accountant, worker.id, Some(10)), &holder_token).await;
    assert_eq!(
        working.provenance.expect("provenance").approved_ceiling,
        vec!["ledger.post".to_string(), "ledger.read".to_string()]
    );

    let widen = UpdateRoleRequest {
        id: accountant.id.0.to_string(),
        description: None,
        permissions: vec![
            "ledger.read".into(),
            "ledger.post".into(),
            "payroll.read".into(),
        ],
    };
    let err = h
        .svc
        .update_role(authed(widen.clone(), &h.admin_token))
        .await
        .expect_err("past the approved ceiling");
    assert_eq!(err.code(), Code::FailedPrecondition, "{err:?}");
    let precondition = tonic_types::StatusExt::get_details_precondition_failure(&err)
        .and_then(|p| p.violations.into_iter().next())
        .expect("a precondition violation");
    assert_eq!(precondition.r#type, "APPROVED_CEILING");
    let err = h
        .svc
        .update_role(authed(widen, &holder_token))
        .await
        .expect_err("no edit right");
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
    let stored = h.storage.get_role(accountant.id).await.unwrap().unwrap();
    assert!(!stored.has_permission("payroll.read"));
}

/// AddToGroup refuses to put an administrator into a group it granted a
/// role, naming the failed precondition rather than an internal error.
#[tokio::test]
async fn a_grantor_is_not_added_to_its_group() {
    use sid_core::models::Group;
    use sid_proto::sid::v1::authz::AddToGroupRequest;
    let h = harness().await;
    let auditor = stored_role(&h, &["ledger.read"]).await;
    let administrator_role = stored_role(&h, &["roles.administer"]).await;
    let team_admin = stored_profile(&h).await;
    let team = Group::new(
        ProjectId::system(),
        format!("g{}", uuid::Uuid::now_v7().simple()),
    );
    h.storage
        .create_group(&team, AuditEntry::system("test", "group").into())
        .await
        .unwrap();
    let mut envelope = accountant_envelope(&auditor);
    envelope.recipient_kinds = vec![RecipientKind::Group as i32];
    let mut grant = assign(&administrator_role, team_admin.id, None);
    grant.admin = Some(envelope);
    granted(&h, grant, &h.admin_token).await;
    let holder_token = issue_token(&test_jwt(), &team_admin, &["openid".to_string()]);
    granted(
        &h,
        AssignRoleRequest {
            principal: Some(Principal::GroupId(team.id.0.to_string())),
            role_id: auditor.id.0.to_string(),
            scope: None,
            expires_at: Some(days(5)),
            admin: None,
        },
        &holder_token,
    )
    .await;

    let err = h
        .svc
        .add_to_group(authed(
            AddToGroupRequest {
                group_id: team.id.0.to_string(),
                profile_id: team_admin.id.to_string(),
            },
            &h.admin_token,
        ))
        .await
        .expect_err("the grantor would reach its own grant");
    assert_eq!(err.code(), Code::FailedPrecondition, "{err:?}");
    let precondition = tonic_types::StatusExt::get_details_precondition_failure(&err)
        .and_then(|p| p.violations.into_iter().next())
        .expect("a precondition violation");
    assert_eq!(precondition.r#type, "GRANTOR_OUTSIDE_GROUP");
    assert!(
        h.storage
            .list_group_members(team.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Every malformed envelope is INVALID_ARGUMENT naming its field, and
/// nothing is stored.
#[tokio::test]
async fn a_malformed_envelope_names_its_field() {
    let h = harness().await;
    let accountant = stored_role(&h, &["ledger.read"]).await;
    let administrator_role = stored_role(&h, &["roles.administer"]).await;
    let holder = stored_profile(&h).await;
    let base = accountant_envelope(&accountant);
    let with = |change: fn(&mut AdminEnvelope)| {
        let mut envelope = base.clone();
        change(&mut envelope);
        envelope
    };
    let cases = [
        (with(|e| e.operations.clear()), "admin.operations"),
        (
            with(|e| e.operations = vec![AdminOperation::Unspecified as i32]),
            "admin.operations",
        ),
        (with(|e| e.operations = vec![99]), "admin.operations"),
        (with(|e| e.role_ids.clear()), "admin.role_ids"),
        (
            with(|e| e.role_ids = vec!["not-a-role".into()]),
            "admin.role_ids",
        ),
        (
            with(|e| e.permission_ceiling.clear()),
            "admin.permission_ceiling",
        ),
        (with(|e| e.recipient_kinds.clear()), "admin.recipient_kinds"),
        (
            with(|e| e.recipient_kinds = vec![RecipientKind::Unspecified as i32]),
            "admin.recipient_kinds",
        ),
        (
            with(|e| e.recipient_group_id = Some("not-a-group".into())),
            "admin.recipient_group_id",
        ),
        (with(|e| e.max_validity = None), "admin.max_validity"),
        (
            with(|e| {
                e.max_validity = Some(prost_types::Duration {
                    seconds: 60,
                    nanos: 1,
                })
            }),
            "admin.max_validity",
        ),
        (
            with(|e| {
                e.max_validity = Some(prost_types::Duration {
                    seconds: 0,
                    nanos: 0,
                })
            }),
            "admin.max_validity",
        ),
    ];
    for (i, (envelope, field)) in cases.into_iter().enumerate() {
        let mut request = assign(&administrator_role, holder.id, None);
        request.admin = Some(envelope);
        let err = h
            .svc
            .assign_role(authed(request, &h.admin_token))
            .await
            .expect_err("malformed");
        assert_eq!(err.code(), Code::InvalidArgument, "case {i}: {err:?}");
        let violation = tonic_types::StatusExt::get_details_bad_request(&err)
            .and_then(|b| b.field_violations.into_iter().next())
            .unwrap_or_else(|| panic!("case {i}: no field violation in {err:?}"));
        assert_eq!(violation.field, field, "case {i}");
    }
    assert!(
        h.storage
            .list_role_assignments_for_profile(holder.id)
            .await
            .unwrap()
            .is_empty(),
        "nothing stored"
    );
}
