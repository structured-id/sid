// SPDX-License-Identifier: AGPL-3.0-only
//! Who may inspect a protected resource's tokens: the built-in token
//! inspector role, assigned through the ordinary role-assignment API to a
//! service identity (an OAuth client or a machine user) on one live
//! resource. It is never project-wide, never a Profile's, never a public
//! client's; an inspector acts under its own restrictions, and when the
//! permission cannot be decided no claim is disclosed.

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, test_client, test_profile};
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::models::{ProjectId, ResourceId, TOKEN_INSPECTOR_ROLE};
use sid_proto::sid::v1::OAuth2IntrospectRequest;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz::list_role_assignments_request::Filter;
use sid_proto::sid::v1::authz::{AssignRoleRequest, ListRoleAssignmentsRequest};
use sid_proto::sid::v1::authz_service_server::AuthzService;
use tonic::{Code, Request};

fn authz(svc: &TestServices) -> AuthzServiceImpl {
    AuthzServiceImpl::new(
        Arc::new(sid_authz::CeAuthzEngine::new(svc.storage.clone())),
        svc.storage.clone(),
        CedarService::new(),
        Arc::new(AtomicBool::new(false)),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
        common::RecordingAuditLog::shared(),
    )
}

fn as_admin<T>(svc: &TestServices, message: T) -> Request<T> {
    let token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

async fn inspector_role(svc: &TestServices) -> String {
    svc.storage
        .list_roles(ProjectId::system())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.key == TOKEN_INSPECTOR_ROLE)
        .expect("provisioned at start")
        .id
        .0
        .to_string()
}

fn on(resource: impl std::fmt::Display) -> Option<String> {
    Some(format!("oauth_resource:{resource}"))
}

/// An administrator assigns the inspector role to a confidential OAuth client
/// on one resource; it is listed under that client.
#[tokio::test]
async fn an_oauth_client_is_assigned_inspection_on_a_resource() {
    let svc = TestServices::new(MockStorage::new().with_client(common::confidential_client()));
    let authz = authz(&svc);
    let userinfo = common::userinfo_resource(&svc).await;
    let assigned = authz
        .assign_role(as_admin(
            &svc,
            AssignRoleRequest {
                principal: Some(Principal::OauthClientId(common::CONFIDENTIAL_CLIENT.into())),
                role_id: inspector_role(&svc).await,
                scope: on(userinfo),
                expires_at: None,
                admin: None,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .assignment
        .unwrap();
    assert_eq!(assigned.scope, on(userinfo));

    let listed = authz
        .list_role_assignments(as_admin(
            &svc,
            ListRoleAssignmentsRequest {
                filter: Some(Filter::OauthClientId(common::CONFIDENTIAL_CLIENT.into())),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.assignments.len(), 1);
    assert_eq!(listed.assignments[0].id, assigned.id);
}

/// The inspector role is refused to a Profile, without a resource scope,
/// project-wide, on an unknown resource, and to a public or unknown client;
/// nothing is stored.
#[tokio::test]
async fn inspection_is_assigned_only_to_a_service_on_one_resource() {
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    let authz = authz(&svc);
    let role = inspector_role(&svc).await;
    let userinfo = common::userinfo_resource(&svc).await;
    let client = || Some(Principal::OauthClientId(common::CONFIDENTIAL_CLIENT.into()));
    let cases = [
        (
            Some(Principal::ProfileId(test_profile().id.to_string())),
            on(userinfo),
            Code::InvalidArgument,
        ),
        (client(), None, Code::InvalidArgument),
        (
            client(),
            Some(format!("project:{}", ProjectId::system().0)),
            Code::InvalidArgument,
        ),
        (client(), on(ResourceId::generate()), Code::NotFound),
        (
            Some(Principal::OauthClientId("test-client".into())),
            on(userinfo),
            Code::InvalidArgument,
        ),
        (
            Some(Principal::OauthClientId("nobody".into())),
            on(userinfo),
            Code::NotFound,
        ),
    ];
    for (i, (principal, scope, code)) in cases.into_iter().enumerate() {
        let err = authz
            .assign_role(as_admin(
                &svc,
                AssignRoleRequest {
                    principal,
                    role_id: role.clone(),
                    scope,
                    expires_at: None,
                    admin: None,
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code, "case {i}: {err:?}");
    }
    assert!(
        svc.storage
            .list_role_assignments_for_oauth_client(common::CONFIDENTIAL_CLIENT)
            .await
            .unwrap()
            .is_empty()
    );
}

/// An expiry that is no timestamp, or already past, is refused: the
/// assignment is never stored with an expiry the caller did not ask for.
#[tokio::test]
async fn an_assignment_expiry_is_a_future_timestamp() {
    let svc = TestServices::new(MockStorage::new().with_client(common::confidential_client()));
    let authz = authz(&svc);
    let userinfo = common::userinfo_resource(&svc).await;
    for (i, expires_at) in [
        prost_types::Timestamp {
            seconds: chrono::Utc::now().timestamp() + 3600,
            nanos: 2_000_000_000,
        },
        prost_types::Timestamp {
            seconds: chrono::Utc::now().timestamp() - 60,
            nanos: 0,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let err = authz
            .assign_role(as_admin(
                &svc,
                AssignRoleRequest {
                    principal: Some(Principal::OauthClientId(common::CONFIDENTIAL_CLIENT.into())),
                    role_id: inspector_role(&svc).await,
                    scope: on(userinfo),
                    expires_at: Some(expires_at),
                    admin: None,
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "case {i}: {err:?}");
    }
    assert!(
        svc.storage
            .list_role_assignments_for_oauth_client(common::CONFIDENTIAL_CLIENT)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A retired resource takes no new inspector.
#[tokio::test]
async fn a_retired_resource_takes_no_inspector() {
    let svc = TestServices::new(MockStorage::new().with_client(common::confidential_client()));
    let authz = authz(&svc);
    let app = sid_core::models::Application {
        id: sid_core::models::ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: "Retiring API".into(),
        system: None,
        revision: 0,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let resource = sid_core::models::ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: svc.issuer.id,
        indicator: sid_core::models::ResourceIndicator::parse("https://resources.example/retiring")
            .unwrap(),
        scopes: vec![],
        state: sid_core::models::ResourceState::Active,
        revision: 0,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let audit = || sid_core::models::AuditEntry::system("test", "api").into();
    svc.storage
        .create_application(&app, None, Some(&resource), audit())
        .await
        .unwrap();
    svc.storage
        .delete_application(app.id, audit())
        .await
        .unwrap();

    let err = authz
        .assign_role(as_admin(
            &svc,
            AssignRoleRequest {
                principal: Some(Principal::OauthClientId(common::CONFIDENTIAL_CLIENT.into())),
                role_id: inspector_role(&svc).await,
                scope: on(resource.id),
                expires_at: None,
                admin: None,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition, "{err:?}");
}

/// A machine user inspects under its own restrictions: from an address
/// outside its allowlist it is refused as at the token endpoint.
#[tokio::test]
async fn a_machine_inspector_keeps_its_restrictions() {
    use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential, OwnerType};
    let mut pdp = sid_core::models::MachineUser::new(
        ProjectId::system(),
        "fenced-pdp",
        "Fenced PDP",
        OwnerType::System,
        "system",
    );
    pdp.restrictions.ip_allowlist = vec!["10.0.0.0/8".into()];
    let secret = "fenced-secret";
    let svc = TestServices::new(
        MockStorage::new()
            .with_machine_user(pdp.clone())
            .with_machine_credential(MachineUserCredential::new(
                pdp.id,
                "kid-fenced",
                MachineCredentialType::ClientSecret,
                sid_authn::bearer_secret::verifier_of(secret),
            )),
    );
    common::grant_inspection(
        &svc,
        sid_core::models::RoleAssignmentPrincipal::MachineUser(pdp.id),
        common::userinfo_resource(&svc).await,
    )
    .await;

    let mut request = common::as_client(
        OAuth2IntrospectRequest {
            token: "any".into(),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        "fenced-pdp",
        secret,
    );
    request
        .extensions_mut()
        .insert(tonic::transport::server::TcpConnectInfo {
            local_addr: None,
            remote_addr: Some("192.0.2.7:4000".parse().unwrap()),
        });
    let err = svc.auth.o_auth2_introspect(request).await.unwrap_err();
    assert_eq!(
        common::oauth_error(&err).as_deref(),
        Some("unauthorized_client")
    );
}

/// A user's token is active only while the sign-in it was issued from
/// lasts: once the session is ended (sign-out, revocation, eviction) the
/// stored session is gone and the token is inactive, read from the store and
/// not only from the revocation cache (resource SDK token-state contract).
#[tokio::test]
async fn an_ended_sign_in_makes_its_token_inactive() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    let userinfo = common::userinfo_resource(&svc).await;
    common::grant_inspection(
        &svc,
        sid_core::models::RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        userinfo,
    )
    .await;
    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;
    let active = || async {
        svc.auth
            .o_auth2_introspect(common::as_client(
                OAuth2IntrospectRequest {
                    token: token.clone(),
                    issuer_handle: svc.issuer.handle.to_string(),
                    ..Default::default()
                },
                common::CONFIDENTIAL_CLIENT,
                common::CONFIDENTIAL_SECRET,
            ))
            .await
            .unwrap()
            .into_inner()
            .active
    };
    assert!(active().await, "a token of a live sign-in");

    let claims = svc
        .issuers
        .verifier(&svc.issuer)
        .await
        .unwrap()
        .validate_access_token_for(
            &token,
            &sid_authn::issuer::userinfo_endpoint(&svc.issuer.canonical_url),
        )
        .unwrap();
    let ended = svc
        .storage
        .delete_session(
            sid_core::models::SessionId::parse(&claims.sid).unwrap(),
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "test",
            ),
            sid_core::models::AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();
    assert_eq!(ended.len(), 1);
    assert!(!active().await, "a token of an ended sign-in");
}

/// When the sign-in a token was issued from cannot be read, the call fails as
/// unavailable and discloses nothing: an unknown state is neither an active
/// token nor a guess that it ended.
#[tokio::test]
async fn an_unreadable_sign_in_discloses_nothing() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    common::grant_inspection(
        &svc,
        sid_core::models::RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        common::userinfo_resource(&svc).await,
    )
    .await;
    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;
    svc.mock_storage.fail_session_reads();

    let result = svc
        .auth
        .o_auth2_introspect(common::as_client(
            OAuth2IntrospectRequest {
                token,
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ))
        .await;
    match result {
        Err(status) => assert_eq!(status.code(), Code::Unavailable, "{status:?}"),
        Ok(answer) => panic!(
            "answered without the sign-in state: {:?}",
            answer.into_inner()
        ),
    }
}

/// When the permission cannot be read the call fails as unavailable and
/// discloses nothing; it is never answered as if permitted.
#[tokio::test]
async fn an_undecidable_permission_discloses_nothing() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    common::grant_inspection(
        &svc,
        sid_core::models::RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        common::userinfo_resource(&svc).await,
    )
    .await;
    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;
    svc.mock_storage.fail_role_reads();

    let result = svc
        .auth
        .o_auth2_introspect(common::as_client(
            OAuth2IntrospectRequest {
                token,
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ))
        .await;
    match result {
        Err(status) => assert_eq!(status.code(), Code::Unavailable, "{status:?}"),
        Ok(answer) => panic!("answered without a decision: {:?}", answer.into_inner()),
    }
}
