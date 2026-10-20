// SPDX-License-Identifier: AGPL-3.0-only
//! Invites managed by a service: a machine user authenticates with its own
//! token for the enrollment API and holds the invite actions on that resource
//! through the built-in invite issuer role. An administrator keeps every
//! invite operation; nobody else gets one.

mod common;

use std::sync::Arc;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, issue_token, test_client, test_profile};
use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential, OwnerType};
use sid_core::models::{
    AuditEntry, INVITE_ACTIONS, INVITE_ISSUER_ROLE, MachineUser, ProjectId, ResourceAccess,
    RoleAssignment, RoleAssignmentPrincipal,
};
use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;
use sid_proto::sid::v1::admin::{
    CreateInviteRequest, GetInviteRequest, InviteCreatorKind, ListInvitesRequest,
    RevokeInviteRequest,
};
use sid_server::grpc::enrollment_service::{EnrollmentServiceImpl, InviteServices};
use tonic::{Code, Request};

const ISSUER: &str = "mu_invite_issuer";
const ISSUER_SECRET: &str = "invite-issuer-secret";

/// An installation with its enrollment API resource, a machine user that may
/// obtain tokens for it and for the authorization API, and the enrollment
/// service admitting services as a server start configures it.
struct Invites {
    svc: TestServices,
    enrollment: EnrollmentServiceImpl,
    machine: MachineUser,
    resource: sid_core::models::ProtectedResource,
}

async fn invites() -> Invites {
    let machine = MachineUser::new(
        ProjectId::system(),
        ISSUER,
        "Onboarding service",
        OwnerType::System,
        "system",
    );
    let svc = TestServices::new(
        MockStorage::new()
            .with_machine_user(machine.clone())
            .with_machine_credential(MachineUserCredential::new(
                machine.id,
                "kid_invite_issuer",
                MachineCredentialType::ClientSecret,
                sid_authn::bearer_secret::verifier_of(ISSUER_SECRET),
            ))
            .with_profile(test_profile())
            .with_client(test_client()),
    );
    let resource =
        sid_authn::issuer::ensure_enrollment_api_resource(svc.storage.as_ref(), &svc.issuer)
            .await
            .unwrap();
    let authorization_api =
        sid_authn::issuer::ensure_authorization_api_resource(svc.storage.as_ref(), &svc.issuer)
            .await
            .unwrap();
    for (api, scopes) in [
        (&resource, INVITE_ACTIONS.map(String::from).to_vec()),
        (
            &authorization_api,
            vec![sid_core::models::AUTHZ_CHECK.to_string()],
        ),
    ] {
        svc.storage
            .set_resource_access(
                &ResourceAccess {
                    client_id: ISSUER.into(),
                    resource_id: api.id,
                    scopes,
                    created_at: chrono::Utc::now(),
                },
                AuditEntry::system("test", "access").into(),
            )
            .await
            .unwrap();
    }
    let tokens = Arc::new(
        sid_authn::resource_token::ResourceTokenVerifier::new(
            svc.issuers.clone(),
            svc.issuer.clone(),
            resource.indicator.clone(),
        )
        .await
        .unwrap(),
    );
    let enrollment = EnrollmentServiceImpl::new(
        svc.storage.clone(),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
    )
    .with_invite_services(InviteServices {
        engine: Arc::new(sid_authz::CeAuthzEngine::new(svc.storage.clone())),
        tokens,
        resource: resource.id,
    });
    Invites {
        svc,
        enrollment,
        machine,
        resource,
    }
}

impl Invites {
    /// Assign the invite issuer role to the machine user on `resource`.
    async fn grant_on(&self, resource: sid_core::models::ResourceId) -> RoleAssignment {
        let role = self
            .svc
            .storage
            .list_roles(ProjectId::system())
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.key == INVITE_ISSUER_ROLE)
            .expect("provisioned at start");
        let assignment = RoleAssignment::new(
            RoleAssignmentPrincipal::MachineUser(self.machine.id),
            role.id,
        )
        .on_resource(resource);
        self.svc
            .storage
            .create_role_assignment(&assignment, AuditEntry::system("test", "grant").into())
            .await
            .unwrap();
        assignment
    }

    /// The machine user's own token for the API at `endpoint`.
    async fn token_for(&self, endpoint: String) -> String {
        use sid_proto::sid::v1::OAuth2TokenRequest;
        use sid_proto::sid::v1::auth_service_server::AuthService;
        self.svc
            .auth
            .o_auth2_token(Request::new(OAuth2TokenRequest {
                grant_type: "client_credentials".into(),
                client_id: Some(ISSUER.into()),
                client_secret: Some(ISSUER_SECRET.into()),
                issuer_handle: self.svc.issuer.handle.to_string(),
                resource: vec![endpoint],
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .access_token
    }

    async fn enrollment_token(&self) -> String {
        self.token_for(sid_authn::issuer::enrollment_api_endpoint(
            &self.svc.issuer.canonical_url,
        ))
        .await
    }
}

fn bearing<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

fn single_use() -> CreateInviteRequest {
    CreateInviteRequest {
        max_uses: 1,
        ..Default::default()
    }
}

fn listing() -> ListInvitesRequest {
    ListInvitesRequest {
        page_size: 100,
        ..Default::default()
    }
}

/// A machine user holding the invite issuer role on the enrollment API
/// creates, reads, lists and revokes invites with its own token; the invite
/// names it, by kind and id, as its creator.
#[tokio::test]
async fn a_service_holding_the_invite_issuer_role_manages_invites() {
    let i = invites().await;
    i.grant_on(i.resource.id).await;
    let token = i.enrollment_token().await;

    let invite = i
        .enrollment
        .create_invite(bearing(&token, single_use()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        InviteCreatorKind::try_from(invite.created_by_kind).unwrap(),
        InviteCreatorKind::MachineUser
    );
    assert_eq!(invite.created_by, i.machine.id.to_string());
    assert_eq!(invite.created_by_name, "Onboarding service");
    assert!(invite.redemptions.is_empty());

    let read = i
        .enrollment
        .get_invite(bearing(
            &token,
            GetInviteRequest {
                invite_id: invite.id.clone(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read.code, invite.code);
    assert_eq!(read.created_by, invite.created_by);

    i.enrollment
        .list_invites(bearing(&token, listing()))
        .await
        .unwrap();

    i.enrollment
        .revoke_invite(bearing(
            &token,
            RevokeInviteRequest {
                invite_id: invite.id.clone(),
            },
        ))
        .await
        .unwrap();
}

/// Without the role on the enrollment API (none at all, the role on another
/// resource, or a revoked assignment) the service is refused, and no invite
/// is stored.
#[tokio::test]
async fn a_service_without_the_role_on_the_enrollment_api_is_refused() {
    let i = invites().await;
    let token = i.enrollment_token().await;
    let refused = |status: tonic::Status| {
        assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
    };
    refused(
        i.enrollment
            .create_invite(bearing(&token, single_use()))
            .await
            .unwrap_err(),
    );

    // The role on another resource grants nothing here.
    let elsewhere =
        sid_authn::issuer::ensure_authorization_api_resource(i.svc.storage.as_ref(), &i.svc.issuer)
            .await
            .unwrap();
    i.grant_on(elsewhere.id).await;
    refused(
        i.enrollment
            .create_invite(bearing(&token, single_use()))
            .await
            .unwrap_err(),
    );
    refused(
        i.enrollment
            .list_invites(bearing(&token, listing()))
            .await
            .unwrap_err(),
    );

    // Granted, then revoked: refused again at once.
    let assignment = i.grant_on(i.resource.id).await;
    i.enrollment
        .create_invite(bearing(&token, single_use()))
        .await
        .unwrap();
    i.svc
        .storage
        .delete_role_assignment(assignment.id, AuditEntry::system("test", "revoke").into())
        .await
        .unwrap();
    refused(
        i.enrollment
            .create_invite(bearing(&token, single_use()))
            .await
            .unwrap_err(),
    );
}

/// The machine user's token for another API is no enrollment credential,
/// whatever roles it holds: it is refused as unauthenticated.
#[tokio::test]
async fn a_token_for_another_api_is_refused() {
    let i = invites().await;
    i.grant_on(i.resource.id).await;
    let other = i
        .token_for(sid_authn::issuer::authorization_api_endpoint(
            &i.svc.issuer.canonical_url,
        ))
        .await;
    let status = i
        .enrollment
        .create_invite(bearing(&other, single_use()))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated, "{status:?}");
}

/// An administrator keeps every invite operation with services admitted, and
/// is recorded as a Profile creator; a user who is no administrator is
/// refused.
#[tokio::test]
async fn administrators_keep_invites_and_other_users_are_refused() {
    let i = invites().await;
    let admin = sid_core::models::ProfileId::generate();
    let admin_token = issue_admin_token(&i.svc.jwt, admin);
    let invite = i
        .enrollment
        .create_invite(bearing(&admin_token, single_use()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        InviteCreatorKind::try_from(invite.created_by_kind).unwrap(),
        InviteCreatorKind::Profile
    );
    assert_eq!(invite.created_by, admin.to_string());
    i.enrollment
        .get_invite(bearing(
            &admin_token,
            GetInviteRequest {
                invite_id: invite.id,
            },
        ))
        .await
        .unwrap();

    let user = test_profile();
    let user_token = issue_token(&i.svc.jwt, &user, &["openid".to_string()]);
    let status = i
        .enrollment
        .create_invite(bearing(&user_token, single_use()))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
}
