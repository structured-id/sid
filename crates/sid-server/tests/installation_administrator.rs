// SPDX-License-Identifier: AGPL-3.0-only
//! The installation administrator role through role administration: it goes
//! only to a Profile, across the whole installation, so every reader of the
//! administrator (the decision, the claim, the last-administrator guard, the
//! token) sees the same assignment; and the last one is kept.

mod common;

use std::sync::Arc;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, test_profile};
use sid_core::models::{AuditEntry, INSTALLATION_SCOPE, ProjectId, Role, RoleAssignment};
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz::{AssignRoleRequest, DeleteRoleRequest, RevokeRoleRequest};
use sid_proto::sid::v1::authz_service_server::AuthzService;
use tonic::{Code, Request};

/// `message` as one new command of `token`'s (a method that promises a safe
/// retry takes an operation key).
fn bearing<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    common::name_new_command(request.metadata_mut());
    request
}

async fn authz(svc: &TestServices) -> sid_server::grpc::authz_service::AuthzServiceImpl {
    for role in [
        Role::installation_administrator(),
        Role::new(ProjectId::SYSTEM, "editor", "Editor"),
    ] {
        svc.storage
            .create_role(&role, AuditEntry::system("test", "role").into())
            .await
            .unwrap();
    }
    sid_server::grpc::authz_service::AuthzServiceImpl::new(
        Arc::new(sid_authz::CeAuthzEngine::new(svc.storage.clone())),
        svc.storage.clone(),
        sid_authz::cedar::CedarService::new(),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
        common::RecordingAuditLog::shared(),
    )
}

fn assign(principal: Principal, role: &Role, scope: Option<&str>) -> AssignRoleRequest {
    AssignRoleRequest {
        principal: Some(principal),
        role_id: Some(role.id.into()),
        scope: scope.map(str::to_owned),
        expires_at: None,
        admin: None,
        policy_admin: None,
    }
}

/// The administrator role is refused to a group, on one resource or without
/// a scope, and the installation scope is refused to any other role: each
/// would make an administrator that only some readers see. Assigned to a
/// Profile across the installation it is accepted, and that Profile
/// administers the installation.
#[tokio::test]
async fn the_administrator_role_goes_to_a_profile_across_the_installation() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let authz = authz(&svc).await;
    let root = common::administrator_token(&svc.jwt, svc.storage.as_ref()).await;
    let administrator = Role::installation_administrator();
    let editor = svc
        .storage
        .list_roles(ProjectId::SYSTEM)
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.key == "editor")
        .unwrap();
    let to_profile = || Principal::ProfileId(profile.id.into());
    let resource = format!(
        "oauth_resource:{}",
        sid_core::models::ResourceId::generate()
    );
    let refused = [
        assign(
            Principal::GroupId(sid_core::models::GroupId::generate().into()),
            &administrator,
            Some(INSTALLATION_SCOPE),
        ),
        assign(to_profile(), &administrator, Some(&resource)),
        assign(to_profile(), &administrator, None),
        assign(to_profile(), &editor, Some(INSTALLATION_SCOPE)),
    ];
    for (n, request) in refused.into_iter().enumerate() {
        let status = authz
            .assign_role(bearing(&root, request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "case {n}: {status:?}");
    }
    assert!(
        !sid_authn::account_roles::administers_installation(svc.storage.as_ref(), profile.id)
            .await
            .unwrap()
    );

    authz
        .assign_role(bearing(
            &root,
            assign(to_profile(), &administrator, Some(INSTALLATION_SCOPE)),
        ))
        .await
        .unwrap();
    assert!(
        sid_authn::account_roles::administers_installation(svc.storage.as_ref(), profile.id)
            .await
            .unwrap()
    );
}

/// Revoking the only administrator assignment is refused as a failed
/// precondition, and the installation keeps its administrator.
#[tokio::test]
async fn the_last_administrator_assignment_is_not_revoked() {
    let owner = test_profile();
    let svc = TestServices::new(MockStorage::unclaimed().with_profile(owner.clone()));
    let authz = authz(&svc).await;
    let only = RoleAssignment::new(
        sid_core::models::RoleAssignmentPrincipal::Profile(owner.id),
        Role::installation_administrator().id,
    )
    .on_installation();
    svc.storage
        .create_role_assignment(&only, AuditEntry::system("test", "assignment").into())
        .await
        .unwrap();
    let root = issue_admin_token(&svc.jwt, owner.id);
    let only = only.id;
    let status = authz
        .revoke_role(bearing(
            &root,
            RevokeRoleRequest {
                assignment_id: Some(only.into()),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition, "{status:?}");
    assert!(svc.storage.admin_exists().await.unwrap());

    // Deleting the role would take the assignment with it: refused the same.
    let status = authz
        .delete_role(bearing(
            &root,
            DeleteRoleRequest {
                id: Some(Role::installation_administrator().id.into()),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition, "{status:?}");
    assert!(svc.storage.admin_exists().await.unwrap());
}

/// The separation-of-duties warnings of the service's configuration file
/// reach CheckSodConflicts: the administrator is warned of the configured
/// conflict, and a service started without the file warns of nothing.
#[tokio::test]
async fn configured_sod_warnings_reach_check_sod_conflicts() {
    use sid_proto::sid::v1::authz::CheckSodConflictsRequest;

    let dir = std::env::temp_dir().join(format!("sid-sod-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("sid.yaml");
    std::fs::write(
        &file,
        "governance:
  sod_warnings:
    - name: author_reviewer
      conflicting_roles: [author, reviewer]
      severity: warning
",
    )
    .unwrap();
    let configured = sid_server::config::installation_config(file.to_str())
        .unwrap()
        .governance
        .sod_warnings;
    std::fs::remove_dir_all(&dir).unwrap();

    let svc = TestServices::new(MockStorage::new());
    let service = authz(&svc)
        .await
        .with_sod_warnings(Arc::new(sid_authz::sod::SodService::new(configured)));
    let root = common::administrator_token(&svc.jwt, svc.storage.as_ref()).await;
    let proposal = || CheckSodConflictsRequest {
        existing_roles: vec!["author".into()],
        proposed_role: "reviewer".into(),
    };
    let warned = service
        .check_sod_conflicts(bearing(&root, proposal()))
        .await
        .unwrap()
        .into_inner();
    assert!(warned.has_conflicts);
    assert_eq!(warned.conflicts[0].rule_name, "author_reviewer");

    let unconfigured = sid_server::config::installation_config(None)
        .unwrap()
        .governance
        .sod_warnings;
    let svc = TestServices::new(MockStorage::new());
    let service = authz(&svc)
        .await
        .with_sod_warnings(Arc::new(sid_authz::sod::SodService::new(unconfigured)));
    let root = common::administrator_token(&svc.jwt, svc.storage.as_ref()).await;
    let quiet = service
        .check_sod_conflicts(bearing(&root, proposal()))
        .await
        .unwrap()
        .into_inner();
    assert!(!quiet.has_conflicts);
}
