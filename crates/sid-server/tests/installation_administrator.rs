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

fn bearing<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

async fn authz(svc: &TestServices) -> sid_authz::grpc::AuthzServiceImpl {
    for role in [
        Role::installation_administrator(),
        Role::new(ProjectId::system(), "editor", "Editor"),
    ] {
        svc.storage
            .create_role(&role, AuditEntry::system("test", "role").into())
            .await
            .unwrap();
    }
    sid_authz::grpc::AuthzServiceImpl::new(
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
        role_id: role.id.0.to_string(),
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
    let root = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    let administrator = Role::installation_administrator();
    let editor = svc
        .storage
        .list_roles(ProjectId::system())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.key == "editor")
        .unwrap();
    let to_profile = || Principal::ProfileId(profile.id.to_string());
    let resource = format!(
        "oauth_resource:{}",
        sid_core::models::ResourceId::generate()
    );
    let refused = [
        assign(
            Principal::GroupId(uuid::Uuid::now_v7().to_string()),
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
                assignment_id: only.0.to_string(),
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
                id: Role::installation_administrator().id.0.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition, "{status:?}");
    assert!(svc.storage.admin_exists().await.unwrap());
}
