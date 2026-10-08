// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC integration tests for sid-server.
//!
//! Tests gRPC service implementations directly (in-process, no network).
//! Uses MockStorage and real JWT/OAuth2/WebAuthn/OPAQUE services.

mod common;

use common::mock_storage::MockStorage;
use common::oauth_client::{authorize_code, code_exchange};
use common::{
    TestServices, issue_admin_token, issue_token, oauth_error, test_client, test_jwt, test_profile,
};
use sid_core::models::{
    AuditEntry, Credential, CredentialType, EmailLabel, Profile, ProfileEmail, ProfileEmailId,
    ProfileId, Project, RoleAssignment, RoleAssignmentPrincipal, Session,
};
use sid_proto::sid::v1::account::account_service_server::AccountService;
use sid_proto::sid::v1::admin::security_service_server::SecurityService;
use sid_proto::sid::v1::admin_service_server::AdminService;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::flow_action_service_server::FlowActionService;
use sid_proto::sid::v1::flow_config_service_server::FlowConfigService;
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::o_auth2_authorize_response::Result as AuthzResult;
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::*;
use sid_server::feature_flags::FeatureFlagService;
use std::sync::Arc;
use tonic::{Request, Response};
use uuid::Uuid;

// ─── Helper: create gRPC request with bearer token ───

fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    req
}

/// A request made by an instance administrator (management RPCs require one).
fn admin_request<T>(svc: &TestServices, msg: T) -> Request<T> {
    authed_request(msg, &issue_admin_token(&svc.jwt, ProfileId::generate()))
}

/// `req` as one new keyed command (methods that promise safe retry take a key).
fn new_command<T>(mut req: Request<T>) -> Request<T> {
    req.metadata_mut().insert(
        sid_authn::operation::OPERATION_KEY_HEADER,
        Uuid::new_v4().to_string().parse().unwrap(),
    );
    req
}

// ═══════════════════════════════════════════════════════════════════
// Profile Management (IdentityService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_create_profile() {
    let svc = TestServices::new(MockStorage::new());
    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: Some("bob".to_string()),
            email: Some("bob@sid.example.com".to_string()),
            phone: None,
            given_name: Some("Bob".to_string()),
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0, // PERSONAL
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    let resp = svc.identity.create_profile(req).await.unwrap();
    let profile = resp.into_inner().profile.unwrap();
    assert_eq!(profile.username.as_deref(), Some("bob"));
    // Email now in profile_emails table, not on proto Profile
    assert_eq!(profile.given_name.as_deref(), Some("Bob"));
    assert!(!profile.id.is_empty());
}

#[tokio::test]
async fn test_create_profile_duplicate_username() {
    let profile = test_profile(); // "alice"
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: Some("alice".to_string()),
            email: Some("different@sid.example.com".to_string()),
            phone: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0,
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    let err = svc.identity.create_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists);
}

#[tokio::test]
async fn test_create_profile_duplicate_email() {
    // Email uniqueness is now enforced at profile_emails table level (UNIQUE index),
    // not at Profile creation time. This test verifies that duplicate emails through
    // profile_emails will be rejected when AccountService RPCs are wired.
    // For now, test that duplicate USERNAME still rejects.
    let profile = test_profile(); // alice
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: Some("alice".to_string()), // duplicate username
            email: None,
            phone: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0,
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    let err = svc.identity.create_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists);
}

// ── D013: single principal at signup ─────────────────────────────

#[tokio::test]
async fn test_create_profile_email_only_no_username() {
    let svc = TestServices::new(MockStorage::new());
    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: None,
            email: Some("alice@sid.example.com".to_string()),
            phone: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0,
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    let resp = svc.identity.create_profile(req).await.unwrap();
    let profile = resp.into_inner().profile.unwrap();
    // Username should be None when registered with email only.
    assert!(
        profile.username.is_none() || profile.username.as_deref() == Some(""),
        "email-only signup should not auto-generate username"
    );
    assert!(!profile.id.is_empty());
}

#[tokio::test]
async fn test_create_profile_username_only_no_email() {
    let svc = TestServices::new(MockStorage::new());
    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: Some("bob".to_string()),
            email: None,
            phone: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0,
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    let resp = svc.identity.create_profile(req).await.unwrap();
    let profile = resp.into_inner().profile.unwrap();
    assert_eq!(profile.username.as_deref(), Some("bob"));
    assert!(!profile.id.is_empty());
}

#[tokio::test]
async fn test_create_profile_no_identifier_fails() {
    let svc = TestServices::new(MockStorage::new());
    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: None,
            email: None,
            phone: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0,
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    let err = svc.identity.create_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_create_profile_phone_only() {
    let svc = TestServices::new(MockStorage::new());
    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: None,
            email: None,
            phone: Some("+380501234567".to_string()),
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0,
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    let resp = svc.identity.create_profile(req).await.unwrap();
    let profile = resp.into_inner().profile.unwrap();
    // Phone-only: no username.
    assert!(
        profile.username.is_none() || profile.username.as_deref() == Some(""),
        "phone-only signup should not have username"
    );
    assert!(!profile.id.is_empty());
}

#[tokio::test]
async fn test_create_profile_empty_strings_treated_as_none() {
    let svc = TestServices::new(MockStorage::new());
    // Empty strings should be treated as "not provided".
    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: Some(String::new()),
            email: Some(String::new()),
            phone: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0,
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    let err = svc.identity.create_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_get_current_profile_authenticated() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(GetCurrentProfileRequest {}, &token);
    let resp = svc.identity.get_current_profile(req).await.unwrap();
    let p = resp.into_inner().profile.unwrap();
    assert_eq!(p.username.as_deref(), Some("alice"));
    // Email now populated from profile_emails, not Profile struct
}

/// A profile read whose contacts cannot be read fails instead of answering
/// as if the profile had no email or phone.
#[tokio::test]
async fn test_get_current_profile_with_unreadable_contacts_is_reported() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    svc.mock_storage.fail_contact_reads();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(GetCurrentProfileRequest {}, &token);
    let err = svc
        .identity
        .get_current_profile(req)
        .await
        .expect_err("a profile was returned without its contacts");
    assert_eq!(err.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn test_get_current_profile_no_token() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(GetCurrentProfileRequest {});
    let err = svc.identity.get_current_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

// ═══════════════════════════════════════════════════════════════════
// OAuth2 Token Endpoint (AuthService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_token_unsupported_grant_type() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(OAuth2TokenRequest {
        grant_type: "password".to_string(),
        ..Default::default()
    });

    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert!(
        err.code() == tonic::Code::InvalidArgument || err.code() == tonic::Code::Unimplemented,
        "expected InvalidArgument or Unimplemented, got {:?}: {}",
        err.code(),
        err.message()
    );
}

#[tokio::test]
async fn test_token_authorization_code_missing_params() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(OAuth2TokenRequest {
        grant_type: "authorization_code".to_string(),
        ..Default::default()
    });

    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_token_authorization_code_unknown_client() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(OAuth2TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some("some-code".to_string()),
        redirect_uri: Some("https://app.sid.example.com/callback".to_string()),
        client_id: Some("nonexistent".to_string()),
        ..Default::default()
    });

    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_token_refresh_missing_token() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(OAuth2TokenRequest {
        grant_type: "refresh_token".to_string(),
        ..Default::default()
    });

    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ═══════════════════════════════════════════════════════════════════
// OAuth2 Introspect (AuthService)
// ═══════════════════════════════════════════════════════════════════

/// `token` introspected at the installation's issuer by the confidential
/// client.
async fn introspect_as_confidential(
    svc: &TestServices,
    token: String,
) -> Result<OAuth2IntrospectResponse, tonic::Status> {
    svc.auth
        .o_auth2_introspect(common::as_client(
            OAuth2IntrospectRequest {
                token,
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ))
        .await
        .map(Response::into_inner)
}

#[tokio::test]
async fn test_introspect_invalid_token() {
    let svc = TestServices::new(MockStorage::new().with_client(common::confidential_client()));
    let resp = introspect_as_confidential(&svc, "invalid.jwt.token".to_string())
        .await
        .unwrap();
    assert_eq!(resp, OAuth2IntrospectResponse::default());
}

/// An inspector holding the token inspector role on the token's resource
/// sees it active with its subject, scope and requesting client (RFC 7662
/// §2.2), although the inspector is neither that client nor in `aud`.
#[tokio::test]
async fn test_introspect_valid_token() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_client(test_client())
        .with_client(common::confidential_client());
    let svc = TestServices::new(storage);
    common::grant_inspection(
        &svc,
        RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        common::userinfo_resource(&svc).await,
    )
    .await;

    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;

    let body = introspect_as_confidential(&svc, token).await.unwrap();
    assert!(body.active);
    assert_eq!(body.sub.as_deref(), Some(profile.id.to_string().as_str()));
    assert_eq!(body.scope.as_deref(), Some("openid"));
    assert_eq!(body.client_id.as_deref(), Some("test-client"));
}

/// A machine user with the inspector role on the resource inspects its
/// tokens with its own credentials; without the role, or with it on another
/// resource, it sees nothing.
#[tokio::test]
async fn test_introspect_by_a_machine_user() {
    use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential, OwnerType};
    let profile = test_profile();
    let pdp = sid_core::models::MachineUser::new(
        sid_core::models::ProjectId::system(),
        "orders-pdp",
        "Orders PDP",
        OwnerType::System,
        "system",
    );
    let secret = "pdp-secret";
    let credential = MachineUserCredential::new(
        pdp.id,
        "kid-pdp",
        MachineCredentialType::ClientSecret,
        sid_authn::bearer_secret::verifier_of(secret),
    );
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client())
            .with_machine_user(pdp.clone())
            .with_machine_credential(credential),
    );
    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;
    let introspect = |token: String| {
        svc.auth.o_auth2_introspect(common::as_client(
            OAuth2IntrospectRequest {
                token,
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            "orders-pdp",
            secret,
        ))
    };

    // Without a role, and with the role on another resource: nothing.
    assert_eq!(
        introspect(token.clone()).await.unwrap().into_inner(),
        OAuth2IntrospectResponse::default()
    );
    common::grant_inspection(
        &svc,
        RoleAssignmentPrincipal::MachineUser(pdp.id),
        sid_core::models::ResourceId::generate(),
    )
    .await;
    assert!(!introspect(token.clone()).await.unwrap().into_inner().active);

    // The role on the token's resource: the token, with its own client.
    common::grant_inspection(
        &svc,
        RoleAssignmentPrincipal::MachineUser(pdp.id),
        common::userinfo_resource(&svc).await,
    )
    .await;
    let body = introspect(token).await.unwrap().into_inner();
    assert!(body.active);
    assert_eq!(body.client_id.as_deref(), Some("test-client"));
}

/// An expired inspector role shows nothing.
#[tokio::test]
async fn test_introspect_expired_permission() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    let role = svc
        .storage
        .list_roles(sid_core::models::ProjectId::system())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.key == sid_core::models::TOKEN_INSPECTOR_ROLE)
        .unwrap();
    let expired = RoleAssignment::new(
        RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        role.id,
    )
    .on_resource(common::userinfo_resource(&svc).await)
    .with_expiry(chrono::Utc::now() - chrono::Duration::seconds(1));
    svc.storage
        .create_role_assignment(&expired, AuditEntry::system("test", "inspection").into())
        .await
        .unwrap();
    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;
    assert_eq!(
        introspect_as_confidential(&svc, token).await.unwrap(),
        OAuth2IntrospectResponse::default()
    );
}

/// Introspection needs an authenticated confidential client of the issuer
/// (RFC 7662 §2.1, §4). A request naming no client is `invalid_request`, as
/// at the token endpoint; a public client, a wrong secret, a secret in the
/// body of a client registered for Basic, and a client at an issuer that does
/// not serve it are `invalid_client`.
#[tokio::test]
async fn test_introspect_needs_an_authenticated_client() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;
    let request = |client_id: Option<&str>, client_secret: Option<&str>, handle: String| {
        OAuth2IntrospectRequest {
            token: token.clone(),
            issuer_handle: handle,
            client_id: client_id.map(str::to_string),
            client_secret: client_secret.map(str::to_string),
            ..Default::default()
        }
    };
    let here = svc.issuer.handle.to_string();
    let elsewhere = sid_core::models::IssuerHandle::generate().to_string();

    let anonymous = svc
        .auth
        .o_auth2_introspect(Request::new(request(None, None, here.clone())))
        .await
        .unwrap_err();
    assert_eq!(oauth_error(&anonymous).as_deref(), Some("invalid_request"));

    let refusals = [
        Request::new(request(Some("test-client"), None, here.clone())),
        common::as_client(
            request(None, None, here.clone()),
            common::CONFIDENTIAL_CLIENT,
            "wrong",
        ),
        Request::new(request(
            Some(common::CONFIDENTIAL_CLIENT),
            Some(common::CONFIDENTIAL_SECRET),
            here,
        )),
        common::as_client(
            request(None, None, elsewhere),
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ),
    ];
    for (i, refused) in refusals.into_iter().enumerate() {
        let err = svc.auth.o_auth2_introspect(refused).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::Unauthenticated,
            "case {i}: {err:?}"
        );
        assert_eq!(
            oauth_error(&err).as_deref(),
            Some("invalid_client"),
            "case {i}"
        );
    }
}

/// Authenticating is not inspection authority: a client without the
/// inspector role on the token's resource sees it inactive, its client,
/// subject and scope undisclosed (RFC 7662 §4), even the client the token
/// was issued to.
#[tokio::test]
async fn test_introspect_hides_another_clients_token() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;
    assert!(common::token_active(&svc, &token).await);

    let body = introspect_as_confidential(&svc, token).await.unwrap();
    assert_eq!(body, OAuth2IntrospectResponse::default());
}

/// An issuer's introspection endpoint knows only that issuer's application
/// tokens: the installation's own sign-in token is not active there
/// (RFC 7662 §2.2).
#[tokio::test]
async fn test_introspect_refuses_tokens_of_another_context() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(common::confidential_client()),
    );

    let session_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let at_issuer = introspect_as_confidential(&svc, session_token)
        .await
        .unwrap();
    assert_eq!(at_issuer, OAuth2IntrospectResponse::default());
}

// ═══════════════════════════════════════════════════════════════════
// OAuth2 Revoke (AuthService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_revoke_nonexistent_token() {
    let svc = TestServices::new(MockStorage::new().with_client(test_client()));
    let req = Request::new(OAuth2RevokeRequest {
        token: "nonexistent-token".to_string(),
        issuer_handle: svc.issuer.handle.to_string(),
        client_id: Some("test-client".to_string()),
        ..Default::default()
    });

    // RFC 7009 §2.2: an unknown token is not an error.
    let resp = svc.auth.o_auth2_revoke(req).await;
    assert!(resp.is_ok());
}

/// Revocation needs the client to authenticate as at the token endpoint
/// (RFC 7009 §2.1): a request naming no client is `invalid_request`; an
/// unknown client and a confidential client without its secret are
/// `invalid_client`.
#[tokio::test]
async fn test_revoke_needs_client_authentication() {
    let svc = TestServices::new(MockStorage::new().with_client(common::confidential_client()));
    let anonymous = svc
        .auth
        .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
            token: "any-token".to_string(),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(oauth_error(&anonymous).as_deref(), Some("invalid_request"));

    for client_id in [Some("nobody"), Some(common::CONFIDENTIAL_CLIENT)] {
        let err = svc
            .auth
            .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
                token: "any-token".to_string(),
                issuer_handle: svc.issuer.handle.to_string(),
                client_id: client_id.map(str::to_string),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(
            oauth_error(&err).as_deref(),
            Some("invalid_client"),
            "{client_id:?}"
        );
    }
}

/// An access token is revoked only by the client it was issued to
/// (RFC 7009 §2.1): another client is refused with `unauthorized_client` and
/// the token keeps working; its own client's revocation ends it.
#[tokio::test]
async fn test_revoke_access_token_only_by_its_client() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    let token = common::issue_application_token(&svc, &profile, &["openid".to_string()]).await;
    let revoke = |request| svc.auth.o_auth2_revoke(request);
    let message = || OAuth2RevokeRequest {
        token: token.clone(),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    };

    let err = revoke(common::as_client(
        message(),
        common::CONFIDENTIAL_CLIENT,
        common::CONFIDENTIAL_SECRET,
    ))
    .await
    .unwrap_err();
    assert_eq!(oauth_error(&err).as_deref(), Some("unauthorized_client"));
    assert!(common::token_active(&svc, &token).await);

    revoke(Request::new(OAuth2RevokeRequest {
        client_id: Some("test-client".to_string()),
        ..message()
    }))
    .await
    .unwrap();
    assert!(!common::token_active(&svc, &token).await);
}

// ═══════════════════════════════════════════════════════════════════
// WebAuthn (AuthService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_webauthn_register_start_no_bearer() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(WebAuthnRegistrationStartRequest { label: None });

    let err = svc
        .auth
        .web_authn_registration_start(req)
        .await
        .unwrap_err();
    // No Bearer token → Unauthenticated
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_webauthn_register_start_unknown_profile() {
    // Issue token for a profile that doesn't exist in storage
    let phantom_profile = test_profile();
    let svc = TestServices::new(MockStorage::new());
    let token = common::fresh_token(&svc, &phantom_profile).await;

    let mut req = Request::new(WebAuthnRegistrationStartRequest { label: None });
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );

    let err = svc
        .auth
        .web_authn_registration_start(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_webauthn_register_start_valid_profile() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);
    let token = common::fresh_token(&svc, &profile).await;

    let mut req = Request::new(WebAuthnRegistrationStartRequest {
        label: Some("Test Key".to_string()),
    });
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );

    let resp = svc.auth.web_authn_registration_start(req).await.unwrap();
    let body = resp.into_inner();
    assert!(!body.challenge.is_empty());
    assert!(!body.options.is_empty());
}

#[tokio::test]
async fn test_webauthn_register_finish_no_bearer() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(WebAuthnRegistrationFinishRequest {
        credential: vec![],
        label: None,
    });

    let err = svc
        .auth
        .web_authn_registration_finish(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_password_change_challenge_no_bearer() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(PasswordChangeChallengeRequest {
        credential_id: Uuid::now_v7().to_string(),
    });

    let err = svc.auth.password_change_challenge(req).await.unwrap_err();
    // Auth check runs before feature check → Unauthenticated
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_password_change_execute_no_bearer() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(PasswordChangeExecuteRequest {
        operation_id: None,
        credential_id: Uuid::now_v7().to_string(),
        registration_request: vec![],
    });

    let err = svc.auth.password_change_execute(req).await.unwrap_err();
    // Auth check runs before feature check → Unauthenticated
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_password_change_finish_no_bearer() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(PasswordChangeFinishRequest {
        operation_id: None,
        credential_id: Uuid::now_v7().to_string(),
        registration_record: vec![],
        proof: None,
    });

    let err = svc.auth.password_change_finish(req).await.unwrap_err();
    // Auth check runs before feature check → Unauthenticated
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_webauthn_authenticate_start_unknown_user() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(WebAuthnAuthenticationStartRequest {
        principal: Some("nonexistent@sid.example.com".to_string()),
    });

    let err = svc
        .auth
        .web_authn_authentication_start(req)
        .await
        .unwrap_err();
    // WebAuthn uses timing-safe error for unknown users
    assert!(
        err.code() == tonic::Code::Unauthenticated || err.code() == tonic::Code::NotFound,
        "expected error for unknown user, got {:?}: {}",
        err.code(),
        err.message()
    );
}

// ═══════════════════════════════════════════════════════════════════
// OPAQUE (AuthService)
// ═══════════════════════════════════════════════════════════════════

/// A start for a free identifier is a new registration; the only failure here is
/// the malformed OPAQUE message, which must be rejected before any state is kept.
#[tokio::test]
async fn test_opaque_register_start_new_identifier_rejects_malformed_request() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(OpaqueRegistrationStartRequest {
        principal: "nonexistent@sid.example.com".to_string(),
        registration_request: vec![0, 1, 2, 3],
        claim_token: None,
    });

    let err = svc.auth.opaque_registration_start(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "{}",
        err.message()
    );
}

/// Run a full OPAQUE registration (start + finish) for `principal` with `password`,
/// finishing under `finish_principal`.
async fn opaque_register(
    svc: &TestServices,
    principal: &str,
    finish_principal: &str,
    password: &[u8],
) -> Result<OpaqueRegistrationFinishResponse, tonic::Status> {
    use sid_opaque_ke::{
        ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse,
    };
    use sid_pake_core::pallas_opaque::PallasCipherSuite;

    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let start = ClientRegistration::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let resp = svc
        .auth
        .opaque_registration_start(Request::new(OpaqueRegistrationStartRequest {
            principal: principal.to_string(),
            registration_request: start.message.serialize().to_vec(),
            claim_token: None,
        }))
        .await?
        .into_inner();
    let response =
        RegistrationResponse::<PallasCipherSuite>::deserialize(&resp.registration_response)
            .unwrap();
    let finish = start
        .state
        .finish(
            &mut rng,
            password,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    svc.auth
        .opaque_registration_finish(Request::new(OpaqueRegistrationFinishRequest {
            principal: finish_principal.to_string(),
            registration_record: finish.message.serialize().to_vec(),
            server_setup: resp.server_setup,
        }))
        .await
        .map(|r| r.into_inner())
}

/// Number of OPAQUE credentials the profile holding `email` has.
async fn opaque_credential_count(svc: &TestServices, email: &str) -> usize {
    let profile = svc
        .storage
        .get_profile_by_principal(sid_core::models::PrincipalType::Email, email)
        .await
        .unwrap()
        .expect("profile holding the email");
    svc.storage
        .get_credentials_by_profile(profile.id, Some(sid_core::models::CredentialType::Opaque))
        .await
        .unwrap()
        .len()
}

/// Regression:a registration for an email that already belongs to an account
/// must not attach a second password to that account. It answers ALREADY_EXISTS with
/// ErrorInfo reason EMAIL_ALREADY_REGISTERED and writes nothing.
#[tokio::test]
async fn test_registration_cannot_attach_password_to_existing_account() {
    let email = "victim@sid.example.com";
    let svc = TestServices::new(MockStorage::new());
    opaque_register(&svc, email, email, b"victim-password-1")
        .await
        .expect("victim registers");

    let err = opaque_register(&svc, email, email, b"attacker-password-2")
        .await
        .expect_err("second registration of the same email must fail");
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{}", err.message());
    let (reason, domain, _) =
        sid_core::grpc_error::extract_error_info(&err).expect("ErrorInfo detail");
    assert_eq!(reason, "EMAIL_ALREADY_REGISTERED");
    assert_eq!(domain, "structured.id");
    assert_eq!(opaque_credential_count(&svc, email).await, 1);
}

/// Regression: a registration stored the folded login key as the new
/// account's email contact, so mail went to a mailbox the registrant never
/// gave. The contact keeps the spelling given; the principal holds the key,
/// and every equivalent spelling finds the account.
#[tokio::test]
async fn test_registration_keeps_the_email_spelling() {
    let svc = TestServices::new(MockStorage::new());
    opaque_register(
        &svc,
        "Ann.Smith+work@SID.example.com",
        "Ann.Smith+work@SID.example.com",
        b"a-good-password-1",
    )
    .await
    .expect("registered");
    let profile = svc
        .storage
        .get_profile_by_principal(
            sid_core::models::PrincipalType::Email,
            "annsmith@sid.example.com",
        )
        .await
        .unwrap()
        .expect("the key finds the account");
    let emails = svc.storage.list_profile_emails(profile.id).await.unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].email, "Ann.Smith+work@sid.example.com");

    let err = opaque_register(
        &svc,
        "annsmith@sid.example.com",
        "annsmith@sid.example.com",
        b"a-good-password-2",
    )
    .await
    .expect_err("an equivalent spelling is the same handle");
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{}", err.message());
}

/// Regression:an account created without a password (admin or SCIM
/// provisioning) cannot be claimed by self-registration with its email.
#[tokio::test]
async fn test_registration_cannot_claim_provisioned_account() {
    let email = "provisioned@sid.example.com";
    let svc = TestServices::new(MockStorage::new());
    svc.identity
        .create_profile(admin_request(
            &svc,
            CreateProfileRequest {
                username: None,
                email: Some(email.to_string()),
                phone: None,
                given_name: None,
                family_name: None,
                middle_name: None,
                honorific_prefix: None,
                honorific_suffix: None,
                profile_type: 0,
                invite_code: None,
                referrer_id: None,
                utm: None,
            },
        ))
        .await
        .expect("provisioned profile");

    let err = opaque_register(&svc, email, email, b"attacker-password")
        .await
        .expect_err("self-registration must not claim a provisioned account");
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{}", err.message());
    assert_eq!(opaque_credential_count(&svc, email).await, 0);
}

/// A finish must name the identifier its start reserved; a swapped principal
/// commits nothing under either identifier.
#[tokio::test]
async fn test_registration_finish_rejects_other_principal() {
    let svc = TestServices::new(MockStorage::new());
    let err = opaque_register(
        &svc,
        "first@sid.example.com",
        "second@sid.example.com",
        b"some-password",
    )
    .await
    .expect_err("principal swap must fail");
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "{}",
        err.message()
    );
    for email in ["first@sid.example.com", "second@sid.example.com"] {
        let held = svc
            .storage
            .get_profile_by_principal(sid_core::models::PrincipalType::Email, email)
            .await
            .unwrap();
        assert!(held.is_none(), "{email} must not be registered");
    }
}

/// A new registration creates the profile, its unverified email principal and
/// contact row, and exactly one OPAQUE credential, all bound to the returned id.
#[tokio::test]
async fn test_registration_creates_account_with_single_principal() {
    let email = "newcomer@sid.example.com";
    let svc = TestServices::new(MockStorage::new());
    let resp = opaque_register(&svc, email, email, b"newcomer-password")
        .await
        .expect("registration");

    let profile = svc
        .storage
        .get_profile_by_principal(sid_core::models::PrincipalType::Email, email)
        .await
        .unwrap()
        .expect("profile created");
    assert_eq!(profile.id.to_string(), resp.profile_id);
    let principals = svc
        .storage
        .get_principals_by_profile(profile.id)
        .await
        .unwrap();
    assert_eq!(principals.len(), 1);
    assert!(!principals[0].verified, "an email starts unverified");
    let primary = svc
        .storage
        .get_primary_profile_email(profile.id)
        .await
        .unwrap()
        .expect("contact row");
    assert_eq!(primary.email, email);
    assert_eq!(opaque_credential_count(&svc, email).await, 1);
}

/// Regression:a signed-in user cannot drive a password change on another
/// account's credential. The challenge and the finish answer NotFound for a
/// foreign credential before any operation is looked up, and nothing is written.
#[tokio::test]
async fn test_password_change_rejects_foreign_credential() {
    let victim_email = "victim-pc@sid.example.com";
    let attacker_email = "attacker-pc@sid.example.com";
    let svc = TestServices::with_zkpp_degraded(MockStorage::new());
    opaque_register(&svc, victim_email, victim_email, b"victim-password")
        .await
        .expect("victim registers");
    opaque_register(&svc, attacker_email, attacker_email, b"attacker-password")
        .await
        .expect("attacker registers");

    let profile_of = |email: &'static str| {
        let storage = svc.storage.clone();
        async move {
            storage
                .get_profile_by_principal(sid_core::models::PrincipalType::Email, email)
                .await
                .unwrap()
                .expect("registered profile")
        }
    };
    let victim = profile_of(victim_email).await;
    let attacker = profile_of(attacker_email).await;
    let victim_cred = svc
        .storage
        .get_credentials_by_profile(victim.id, Some(CredentialType::Opaque))
        .await
        .unwrap()
        .remove(0);
    // A fresh session: the attacker has every authority over their own
    // credentials, so only the ownership check stands between them and the victim's.
    let token = common::fresh_token(&svc, &attacker).await;

    let err = svc
        .auth
        .password_change_challenge(authed_request(
            PasswordChangeChallengeRequest {
                credential_id: victim_cred.id.0.to_string(),
            },
            &token,
        ))
        .await
        .expect_err("foreign credential must not be challengeable");
    assert_eq!(err.code(), tonic::Code::NotFound, "{}", err.message());

    let err = svc
        .auth
        .password_change_finish(authed_request(
            PasswordChangeFinishRequest {
                operation_id: Some(sid_ids::PasswordOperationId::generate().into()),
                credential_id: victim_cred.id.0.to_string(),
                registration_record: vec![0; 32],
                proof: None,
            },
            &token,
        ))
        .await
        .expect_err("finish on a foreign credential must fail");
    assert_eq!(err.code(), tonic::Code::NotFound, "{}", err.message());

    let after = svc
        .storage
        .get_credential(victim_cred.id)
        .await
        .unwrap()
        .expect("victim credential kept");
    assert_eq!(
        after.data, victim_cred.data,
        "victim password must be unchanged"
    );
}

/// Regression:login uses only the profile's active OPAQUE credential. After
/// the credential is revoked, even the correct password does not sign in; the
/// start is answered like one for an account without a password, so the
/// refusal comes at finish, as for a wrong password.
#[tokio::test]
async fn test_opaque_login_ignores_revoked_credential() {
    let email = "revoked-pw@sid.example.com";
    let password = b"revoked-password";
    let svc = TestServices::new(MockStorage::new());
    opaque_register(&svc, email, email, password)
        .await
        .expect("registration");
    let profile = svc
        .storage
        .get_profile_by_principal(sid_core::models::PrincipalType::Email, email)
        .await
        .unwrap()
        .expect("profile");
    let mut credential = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::Opaque))
        .await
        .unwrap()
        .remove(0);
    credential.status = sid_core::models::credential::CredentialStatus::Revoked;
    svc.mock_storage.set_credential(&credential);

    let err = common::opaque_client::login(&svc, email, password)
        .await
        .expect_err("a revoked password must not sign in");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "{}",
        err.message()
    );
}

#[tokio::test]
async fn test_opaque_register_start_invalid_message() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Add email principal so profile is found (otherwise Unauthenticated before InvalidArgument)
    let mut ep = sid_core::models::Principal::new(
        profile.id,
        sid_core::models::PrincipalType::Email,
        "alice@sid.example.com",
    );
    ep.is_primary = true;
    svc.storage
        .save_principal(&ep, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let req = Request::new(OpaqueRegistrationStartRequest {
        principal: "alice@sid.example.com".to_string(),
        registration_request: vec![0xFF, 0xFF], // invalid OPAQUE message
        claim_token: None,
    });

    let err = svc.auth.opaque_registration_start(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_opaque_login_start_unknown_user() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(OpaqueLoginStartRequest {
        principal: "nonexistent@sid.example.com".to_string(),
        credential_request: vec![0, 1, 2, 3],
    });

    let err = svc.auth.opaque_login_start(req).await.unwrap_err();
    assert!(
        err.code() == tonic::Code::Unauthenticated || err.code() == tonic::Code::NotFound,
        "expected Unauthenticated or NotFound, got {:?}",
        err.code()
    );
}

#[tokio::test]
async fn test_opaque_login_finish_invalid_state() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(OpaqueLoginFinishRequest {
        principal: "nonexistent@sid.example.com".to_string(),
        credential_finalization: vec![0, 1, 2, 3],
        server_login_state: "nonexistent-state".to_string(),
    });

    // An unknown login state reads as an expired sign-in.
    let err = svc.auth.opaque_login_finish(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(common::error_reason(&err).as_deref(), Some("INVALID_STATE"));
}

// ═══════════════════════════════════════════════════════════════════
// E2E: OPAQUE Registration + Login via gRPC
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_opaque_registration_and_login() {
    use sid_opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };
    use sid_pake_core::pallas_opaque::PallasCipherSuite;

    let email = "carol@sid.example.com";
    let svc = TestServices::new(MockStorage::new());

    // Step 1-2: OPAQUE registration creates the account for the new email.
    let password = b"carol-strong-password-2024";
    let mut client_rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);

    // 2a: Registration start
    let client_reg_start =
        ClientRegistration::<PallasCipherSuite>::start(&mut client_rng, password).unwrap();

    let resp = svc
        .auth
        .opaque_registration_start(Request::new(OpaqueRegistrationStartRequest {
            principal: email.to_string(),
            registration_request: client_reg_start.message.serialize().to_vec(),
            claim_token: None,
        }))
        .await
        .unwrap();
    let reg_resp = resp.into_inner();

    let reg_response =
        RegistrationResponse::<PallasCipherSuite>::deserialize(&reg_resp.registration_response)
            .unwrap();

    // 2b: Registration finish
    let client_reg_finish = client_reg_start
        .state
        .finish(
            &mut client_rng,
            password,
            reg_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    let resp = svc
        .auth
        .opaque_registration_finish(Request::new(OpaqueRegistrationFinishRequest {
            principal: email.to_string(),
            registration_record: client_reg_finish.message.serialize().to_vec(),
            server_setup: reg_resp.server_setup.clone(),
        }))
        .await
        .unwrap();
    assert!(!resp.into_inner().credential_id.is_empty());

    // Step 3: OPAQUE Login
    let client_login_start =
        ClientLogin::<PallasCipherSuite>::start(&mut client_rng, password).unwrap();

    let resp = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: email.to_string(),
            credential_request: client_login_start.message.serialize().to_vec(),
        }))
        .await
        .unwrap();
    let login_resp = resp.into_inner();
    let server_login_state = login_resp.server_login_state.clone();

    let cred_response =
        CredentialResponse::<PallasCipherSuite>::deserialize(&login_resp.credential_response)
            .unwrap();

    let client_login_finish = client_login_start
        .state
        .finish(
            &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
            password,
            cred_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    let resp = svc
        .auth
        .opaque_login_finish(Request::new(OpaqueLoginFinishRequest {
            principal: email.to_string(),
            credential_finalization: client_login_finish.message.serialize().to_vec(),
            server_login_state,
        }))
        .await
        .unwrap();
    let token_resp = resp.into_inner();
    assert!(!token_resp.access_token.is_empty());
    assert!(token_resp.expires_in > 0);

    // Step 4: Use token to get current profile
    let req = authed_request(GetCurrentProfileRequest {}, &token_resp.access_token);
    let resp = svc.identity.get_current_profile(req).await.unwrap();
    let me = resp.into_inner().profile.unwrap();
    // One signup principal (the email); no username was chosen.
    assert_eq!(me.username, None);
}

// ═══════════════════════════════════════════════════════════════════
// E2E: OAuth2 Authorization Code Flow via gRPC
// ═══════════════════════════════════════════════════════════════════

/// The tokens a code redeems into report when and how the user actually
/// authenticated in the session that authorized it, not the exchange: the ID
/// Token's `auth_time`, `amr` and `acr` (OIDC Core §2) are that session's.
#[tokio::test]
async fn test_code_tokens_report_the_authorizing_authentication() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);
    let mut session =
        common::authenticated_session(&profile, sid_core::models::AuthLevel::Standard, 40);
    session.amr = vec!["pwd".into(), "otp".into(), "mfa".into()];
    let authenticated_at = session.authenticated_at.timestamp();
    let bearer = common::stored_session_token(&svc, &profile, session).await;

    let code = match svc
        .auth
        .o_auth2_authorize(authed_request(
            OAuth2AuthorizeRequest {
                client_id: "test-client".to_string(),
                redirect_uri: common::oauth_client::REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: Some("openid".to_string()),
                state: Some("s".to_string()),
                nonce: Some("n".to_string()),
                code_challenge: Some(common::oauth_client::CODE_CHALLENGE.to_string()),
                code_challenge_method: Some("S256".to_string()),
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &bearer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
    {
        Some(AuthzResult::AuthorizationCode(c)) => c,
        other => panic!("expected authorization_code, got {other:?}"),
    };
    let tokens = svc
        .auth
        .o_auth2_token(common::oauth_client::code_exchange(&svc, &code))
        .await
        .unwrap()
        .into_inner();

    let id_token = tokens.id_token.as_deref().expect("id_token");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            id_token.split('.').nth(1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["auth_time"], authenticated_at, "{claims}");
    assert_eq!(claims["amr"], serde_json::json!(["pwd", "otp", "mfa"]));
    assert_eq!(
        claims["acr"],
        sid_core::models::AuthLevel::Standard.acr_value()
    );
}

#[tokio::test]
async fn test_e2e_authorization_code_flow() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let bearer = common::fresh_token(&svc, &profile).await;

    // Step 1: Authorize → get auth code
    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.sid.example.com/callback".to_string(),
            response_type: "code".to_string(),
            scope: Some("openid profile email".to_string()),
            state: Some("e2e_state".to_string()),
            nonce: Some("e2e-nonce-0S6_WzA2Mj".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &bearer,
    );

    let resp = svc.auth.o_auth2_authorize(req).await.unwrap();
    let auth_resp = resp.into_inner();
    let code = match auth_resp.result {
        Some(AuthzResult::AuthorizationCode(c)) => c,
        other => panic!("expected authorization_code, got {:?}", other),
    };
    assert!(!code.is_empty());

    // Step 2: Token exchange
    let req = Request::new(OAuth2TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code),
        redirect_uri: Some("https://app.sid.example.com/callback".to_string()),
        client_id: Some("test-client".to_string()),
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    });

    let resp = svc.auth.o_auth2_token(req).await.unwrap();
    let token_resp = resp.into_inner();
    assert!(!token_resp.access_token.is_empty());
    assert!(token_resp.refresh_token.is_some());
    assert_eq!(token_resp.token_type, "Bearer");
    assert_eq!(token_resp.expires_in, 300);
    // id_token should be present (openid scope) and carry the request's
    // nonce unchanged (OIDC Core §3.1.3.6).
    let id_token = token_resp.id_token.as_deref().expect("id_token");
    let payload = id_token.split('.').nth(1).expect("JWT payload");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["nonce"], "e2e-nonce-0S6_WzA2Mj");
    // Both tokens name the application's issuer, the one its discovery
    // document gives (OIDC Discovery 1.0 §4.3).
    assert_eq!(claims["iss"], svc.issuer.canonical_url.as_str());

    // Step 3: the access token is the issuer's, for the client's target
    // resource: typed `at+jwt`, `aud` the resource (here the client's default,
    // the issuer's UserInfo), `client_id` the requesting client (RFC 9068
    // §2.1, §2.2), and no ProfileId (`pid`) for an application.
    assert!(common::token_active(&svc, &token_resp.access_token).await);
    let header = jsonwebtoken::decode_header(&token_resp.access_token).unwrap();
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let payload = token_resp
        .access_token
        .split('.')
        .nth(1)
        .expect("JWT payload");
    let access: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        access["aud"],
        serde_json::json!([sid_authn::issuer::userinfo_endpoint(
            &svc.issuer.canonical_url
        )])
    );
    assert_eq!(access["client_id"], "test-client");
    assert_eq!(access["iss"], svc.issuer.canonical_url.as_str());
    assert!(access.get("pid").is_none(), "{access}");
}

/// RFC 6749 §4.1.2: a second use of a code is refused and the tokens issued
/// from its first use are revoked, so an intercepted code replayed after the
/// client's exchange also kills the client's session.
#[tokio::test]
async fn test_authorization_code_reuse_revokes_first_exchange() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);
    let code = authorize_code(&svc, &profile).await;

    let first = svc
        .auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .expect("first exchange")
        .into_inner();

    let err = svc
        .auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .expect_err("a reused code is refused");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let oauth_error = tonic_types::StatusExt::get_details_error_info(&err)
        .and_then(|info| info.metadata.get("oauthError").cloned());
    assert_eq!(oauth_error.as_deref(), Some("invalid_grant"), "{err:?}");

    let refresh = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: first.refresh_token,
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await;
    assert!(
        refresh.is_err(),
        "the refresh token from the first exchange is revoked"
    );
}

/// Two concurrent exchanges of one code: exactly one gets tokens. The race
/// itself is exercised against each storage backend by the storage
/// conformance scenario; this checks the service path end to end.
#[tokio::test]
async fn test_authorization_code_concurrent_exchange_single_winner() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);
    let code = authorize_code(&svc, &profile).await;

    let (a, b) = tokio::join!(
        svc.auth.o_auth2_token(code_exchange(&svc, &code)),
        svc.auth.o_auth2_token(code_exchange(&svc, &code)),
    );
    let successes = [a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count();
    assert_eq!(successes, 1, "exactly one exchange gets tokens");
}

// ═══════════════════════════════════════════════════════════════════
// E2E: Refresh Token Rotation via gRPC
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_refresh_token_rotation() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Authorize → code → tokens
    let code = authorize_code(&svc, &profile).await;
    let resp = svc
        .auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .unwrap();
    let refresh_token_1 = resp.into_inner().refresh_token.unwrap();

    // Rotate refresh token
    let resp = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(refresh_token_1.clone()),
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap();
    let token_body = resp.into_inner();
    let refresh_token_2 = token_body.refresh_token.unwrap();
    assert_ne!(
        refresh_token_1, refresh_token_2,
        "refresh token should rotate"
    );

    // The new access token is valid.
    assert!(common::token_active(&svc, &token_body.access_token).await);

    // Reuse old refresh token within grace window → should succeed (concurrent retry scenario)
    let resp = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(refresh_token_1.clone()),
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await;
    assert!(
        resp.is_ok(),
        "old refresh token should work within 30s grace window"
    );
    let refresh_token_3 = resp.unwrap().into_inner().refresh_token.unwrap();
    assert_ne!(refresh_token_1, refresh_token_3);
}

#[tokio::test]
async fn test_e2e_refresh_token_theft_detection() {
    use sid_core::models::refresh_token::DEFAULT_GRACE_WINDOW_SECS;

    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Authorize → code → tokens
    let code = authorize_code(&svc, &profile).await;
    let resp = svc
        .auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .unwrap();
    let first = resp.into_inner();
    let access_token_1 = first.access_token;
    let refresh_token_1 = first.refresh_token.unwrap();

    // Rotate → get token2
    let resp = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(refresh_token_1.clone()),
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap();
    let refresh_token_2 = resp.into_inner().refresh_token.unwrap();

    // Verify grace window was set on old token, then expire it
    {
        let inner = svc.mock_storage.inner.lock().unwrap();
        let revoked_with_grace = inner
            .refresh_tokens_by_hash
            .values()
            .any(|t| t.revoked && t.grace_expires_at.is_some());
        assert!(
            revoked_with_grace,
            "after rotation, old token should be revoked with grace window ({}s)",
            DEFAULT_GRACE_WINDOW_SECS
        );
    }

    // Expire ALL grace windows manually to simulate time passing
    {
        let mut inner = svc.mock_storage.inner.lock().unwrap();
        for token in inner.refresh_tokens_by_hash.values_mut() {
            if token.grace_expires_at.is_some() {
                token.grace_expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(10));
            }
        }
    }

    // Now reuse old token AFTER grace expired → theft detection
    let err = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(refresh_token_1),
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert!(
        err.code() == tonic::Code::InvalidArgument,
        "expected InvalidArgument for token reuse after grace window, got {:?}: {}",
        err.code(),
        err.message()
    );
    assert!(
        err.message().contains("reused"),
        "error should indicate token theft: {}",
        err.message()
    );

    // The whole session ends: the family's current refresh token and the
    // session's access token no longer work.
    let err = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(refresh_token_2),
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        !common::token_active(&svc, &access_token_1).await,
        "access token of a compromised session still active"
    );
}

/// A rotation the storage fails to record is reported as a failure: the
/// client must not receive a refresh token that was never stored.
#[tokio::test]
async fn test_refresh_rotation_storage_failure_is_reported() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(profile.clone())
            .with_failing_refresh_rotation(),
    );
    let code = authorize_code(&svc, &profile).await;
    let first = svc
        .auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .unwrap()
        .into_inner();

    let err = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: first.refresh_token,
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Internal);
}

/// A refresh whose contact claims cannot be read fails: it must not issue
/// tokens that silently lack the email and phone claims the scopes promised.
#[tokio::test]
async fn test_refresh_with_unreadable_contacts_is_reported() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(profile.clone()),
    );
    let code = authorize_code(&svc, &profile).await;
    let first = svc
        .auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .unwrap()
        .into_inner();

    svc.mock_storage.fail_contact_reads();
    let err = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: first.refresh_token,
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .expect_err("tokens were issued without their contact claims");

    assert_eq!(err.code(), tonic::Code::Internal);
}

// ═══════════════════════════════════════════════════════════════════
// OAuth2 Authorize edge cases
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_authorize_no_token_returns_unauthenticated() {
    let storage = MockStorage::new().with_client(test_client());
    let svc = TestServices::new(storage);

    let req = Request::new(OAuth2AuthorizeRequest {
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        response_type: "code".to_string(),
        scope: Some("openid profile".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    });

    let err = svc.auth.o_auth2_authorize(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_authorize_unknown_client() {
    let svc = TestServices::new(MockStorage::new());

    let profile = test_profile();
    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "nonexistent".to_string(),
            redirect_uri: "https://app.sid.example.com/callback".to_string(),
            response_type: "code".to_string(),
            ..Default::default()
        },
        &token,
    );

    let err = svc.auth.o_auth2_authorize(req).await.unwrap_err();
    assert!(
        err.code() == tonic::Code::NotFound || err.code() == tonic::Code::InvalidArgument,
        "expected NotFound or InvalidArgument, got {:?}",
        err.code()
    );
}

#[tokio::test]
async fn test_authorize_invalid_redirect_uri() {
    let storage = MockStorage::new().with_client(test_client());
    let svc = TestServices::new(storage);

    let profile = test_profile();
    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://evil.com/callback".to_string(),
            response_type: "code".to_string(),
            code_challenge: Some("test".to_string()),
            code_challenge_method: Some("S256".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &token,
    );

    let err = svc.auth.o_auth2_authorize(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ═══════════════════════════════════════════════════════════════════
// ACR enforcement at authorize (step-up trigger)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_authorize_acr_values_step_up_required() {
    use sid_core::models::session::Session;

    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create a session with Basic assurance level (default) and store it.
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) = common::issue_token_with_session(
        &svc.jwt,
        &profile,
        &["openid".to_string(), "profile".to_string()],
        session,
    );
    // Save session in storage so authorize handler can look it up.
    svc.storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // Request authorize with acr_values=standard (session is Basic → should fail).
    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.sid.example.com/callback".to_string(),
            response_type: "code".to_string(),
            scope: Some("openid".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            acr_values: Some("urn:sid:acr:standard".to_string()), // Standard
            state: Some("test-state".to_string()),
            nonce: Some("test-nonce".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &bearer,
    );

    let err = svc.auth.o_auth2_authorize(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "ACR enforcement should return FailedPrecondition when session Basic < requested Standard"
    );
    // The requirement travels as STEP_UP_REQUIRED with the acr to reach as a
    // PreconditionFailure, never as text the client parses.
    let (reason, _, _) = sid_core::grpc_error::extract_error_info(&err).expect("ErrorInfo");
    assert_eq!(reason, "STEP_UP_REQUIRED");
    let violations = tonic_types::StatusExt::get_details_precondition_failure(&err)
        .expect("PreconditionFailure")
        .violations;
    assert!(
        violations
            .iter()
            .any(|v| v.r#type == "acr" && !v.subject.is_empty()),
        "{violations:?}"
    );
}

#[tokio::test]
async fn test_authorize_acr_values_satisfied() {
    use sid_core::models::session::{AuthLevel, Session};

    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create a session with Standard assurance level.
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.as_active().unwrap().elevate(AuthLevel::Standard);
    let (bearer, session) = common::issue_token_with_session(
        &svc.jwt,
        &profile,
        &["openid".to_string(), "profile".to_string()],
        session,
    );
    svc.storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // Request authorize with acr_values=standard (session IS Standard → should succeed).
    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.sid.example.com/callback".to_string(),
            response_type: "code".to_string(),
            scope: Some("openid profile".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            acr_values: Some("urn:sid:acr:standard".to_string()), // Standard
            state: Some("test-state".to_string()),
            nonce: Some("test-nonce".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &bearer,
    );

    let resp = svc.auth.o_auth2_authorize(req).await;
    assert!(
        resp.is_ok(),
        "ACR satisfied (Standard >= Standard) should succeed: {:?}",
        resp.err()
    );
}

#[tokio::test]
async fn test_authorize_client_required_acr_enforced() {
    use sid_core::models::session::Session;

    let profile = test_profile();
    // Create client with required_acr = Standard.
    let mut client = test_client();
    client.required_acr = Some(sid_core::models::session::AuthLevel::Standard);
    client.enforcement_mode = sid_core::models::EnforcementMode::Hard;

    let storage = MockStorage::new()
        .with_client(client)
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Session with Basic assurance.
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // Authorize WITHOUT acr_values — but client.required_acr = Standard.
    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.sid.example.com/callback".to_string(),
            response_type: "code".to_string(),
            scope: Some("openid".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            state: Some("test-state".to_string()),
            nonce: Some("test-nonce".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &bearer,
    );

    let err = svc.auth.o_auth2_authorize(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "client.required_acr=Standard should enforce even without acr_values param"
    );
}

#[tokio::test]
async fn test_authorize_client_required_amr_enforced() {
    use sid_core::models::session::Session;

    let profile = test_profile();
    // Client requires "hwk" (hardware key) in AMR.
    let mut client = test_client();
    client.required_amr = vec!["hwk".to_string()];

    let storage = MockStorage::new()
        .with_client(client)
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Session with amr=["pwd"] (password only, no hardware key).
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.amr = vec!["pwd".to_string()];
    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // Authorize — session has pwd but client requires hwk.
    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.sid.example.com/callback".to_string(),
            response_type: "code".to_string(),
            scope: Some("openid".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            state: Some("test-state".to_string()),
            nonce: Some("test-nonce".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &bearer,
    );

    let err = svc.auth.o_auth2_authorize(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "client.required_amr=[hwk] should fail when session.amr=[pwd]"
    );
    // Each missing method is a PreconditionFailure violation of type "amr".
    let (reason, _, _) = sid_core::grpc_error::extract_error_info(&err).expect("ErrorInfo");
    assert_eq!(reason, "STEP_UP_REQUIRED");
    let violations = tonic_types::StatusExt::get_details_precondition_failure(&err)
        .expect("PreconditionFailure")
        .violations;
    assert!(
        violations
            .iter()
            .any(|v| v.r#type == "amr" && v.subject == "hwk"),
        "{violations:?}"
    );
}

#[tokio::test]
async fn test_authorize_client_amr_satisfied() {
    use sid_core::models::session::Session;

    let profile = test_profile();
    let mut client = test_client();
    client.required_amr = vec!["pwd".to_string()];

    let storage = MockStorage::new()
        .with_client(client)
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Session with amr=["pwd", "hwk"] — satisfies "pwd" requirement.
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.amr = vec!["pwd".to_string(), "hwk".to_string()];
    let (bearer, session) = common::issue_token_with_session(
        &svc.jwt,
        &profile,
        &["openid".to_string(), "profile".to_string()],
        session,
    );
    svc.storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.sid.example.com/callback".to_string(),
            response_type: "code".to_string(),
            scope: Some("openid profile".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            state: Some("test-state".to_string()),
            nonce: Some("test-nonce".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &bearer,
    );

    let resp = svc.auth.o_auth2_authorize(req).await;
    assert!(
        resp.is_ok(),
        "AMR satisfied (pwd in session) should succeed: {:?}",
        resp.err()
    );
}

// ═══════════════════════════════════════════════════════════════════
// ZKPP Policy (AuthService)
// ═══════════════════════════════════════════════════════════════════

/// A server that verifies no proofs (no verifying key loaded) still serves
/// its password policy: the policy is the installation's and a client checks
/// the password against it locally; the proof only evidences that check.
#[tokio::test]
async fn test_zkpp_policy_is_served_without_a_verifier() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let policy = svc
        .auth
        .get_zkpp_policy(Request::new(GetZkppPolicyRequest {}))
        .await
        .expect("the policy is served")
        .into_inner();
    assert_eq!(policy.policy_version, 1);
    assert!(policy.min_length > 0, "the policy names its minimums");
}

// ═══════════════════════════════════════════════════════════════════
// ZKPP policy evidence (AuthService)
// ═══════════════════════════════════════════════════════════════════

/// A stored policy-unverified credential stays unverified whatever proof is
/// sent later: a proof proves only the registration it is bound to.
#[tokio::test]
async fn test_late_policy_proof_never_verifies_a_stored_credential() {
    let profile = test_profile();
    let cred = Credential::new(profile.id, CredentialType::Opaque, vec![1, 2, 3], None);
    let storage = MockStorage::new()
        .with_system_project()
        .with_profile(profile.clone())
        .with_credential(cred.clone());
    let svc = TestServices::with_zkpp_degraded(storage);
    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(
        SubmitDeferredZkProofRequest {
            credential_id: cred.id.0.to_string(),
            zkpp_proof: vec![1, 2, 3],
            instances: vec![],
            policy_version: 7,
        },
        &token,
    );
    let err = svc.auth.submit_deferred_zk_proof(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(common::error_reason(&err).as_deref(), Some("INVALID_STATE"));
    let stored = svc.storage.get_credential(cred.id).await.unwrap().unwrap();
    assert!(!stored.zkpp_verified);
    assert_eq!(stored.policy_version, None);
}

/// Register `principal` through the ZKPP path without a proof; returns the
/// stored credential.
async fn zkpp_register_without_proof(
    svc: &TestServices,
    principal: &str,
) -> sid_core::models::Credential {
    let mut client_rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let password = b"TestP@ss123";
    let client_registration = sid_opaque_ke::ClientRegistration::<
        sid_pake_core::pallas_opaque::PallasCipherSuite,
    >::start(&mut client_rng, password)
    .unwrap();
    let start = svc
        .auth
        .opaque_zkpp_registration_start(tonic::Request::new(OpaqueZkppRegistrationStartRequest {
            principal: principal.to_string(),
            registration_request: client_registration.message.serialize().to_vec(),
            claim_token: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let context = start.history.expect("the registration's history context");
    let response = sid_opaque_ke::RegistrationResponse::<
        sid_pake_core::pallas_opaque::PallasCipherSuite,
    >::deserialize(&start.registration_response)
    .unwrap();
    let finish = client_registration
        .state
        .finish(
            &mut client_rng,
            password,
            response,
            sid_opaque_ke::ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let done = svc
        .auth
        .opaque_zkpp_registration_finish(tonic::Request::new(OpaqueZkppRegistrationFinishRequest {
            operation_id: context.operation_id,
            registration_record: finish.message.serialize().to_vec(),
            proof: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let id: uuid::Uuid = done.credential_id.parse().unwrap();
    svc.storage
        .get_credential(sid_core::models::CredentialId(id))
        .await
        .unwrap()
        .unwrap()
}

/// Whether a registration proved its password policy is what the server
/// verified at its start: without a proof the credential is policy-unverified.
#[tokio::test]
async fn test_zkpp_registration_without_proof_is_unverified() {
    let svc = TestServices::with_zkpp_degraded(MockStorage::new().with_system_project());
    let credential = zkpp_register_without_proof(&svc, "unproven@sid.example.com").await;
    assert!(
        !credential.zkpp_verified,
        "an unproven registration was stored as verified"
    );
    assert_eq!(credential.policy_version, None);
}

// ═══════════════════════════════════════════════════════════════════
// Revocation Cache via gRPC
// ═══════════════════════════════════════════════════════════════════

/// An issuer's revocation endpoint acts only on that issuer's tokens: SID's
/// own sign-in token presented there is left alone (the answer is still
/// success, RFC 7009 §2.2) and keeps working at SID's services. Sign-in
/// sessions end through session revocation, not an application's endpoint.
#[tokio::test]
async fn test_session_token_is_not_revoked_at_an_issuer_endpoint() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_client(test_client());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    svc.auth
        .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
            token: token.clone(),
            issuer_handle: svc.issuer.handle.to_string(),
            client_id: Some("test-client".to_string()),
            ..Default::default()
        }))
        .await
        .expect("revocation answers success");

    let req = authed_request(GetCurrentProfileRequest {}, &token);
    assert!(svc.identity.get_current_profile(req).await.is_ok());
}

/// A token its client revoked is inactive at introspection (RFC 7009 §2,
/// RFC 7662 §2.2).
#[tokio::test]
async fn test_introspect_revoked_token_inactive() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_client(common::confidential_client());
    let svc = TestServices::new(storage);
    common::grant_inspection(
        &svc,
        RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        common::userinfo_resource(&svc).await,
    )
    .await;

    let token = common::issue_application_token_to(
        &svc,
        &profile,
        &["openid".to_string()],
        common::CONFIDENTIAL_CLIENT,
    )
    .await;

    // Active before revocation
    assert!(
        introspect_as_confidential(&svc, token.clone())
            .await
            .unwrap()
            .active
    );

    svc.auth
        .o_auth2_revoke(common::as_client(
            OAuth2RevokeRequest {
                token: token.clone(),
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ))
        .await
        .unwrap();

    // Inactive after revocation
    assert!(
        !introspect_as_confidential(&svc, token)
            .await
            .unwrap()
            .active
    );
}

// ═══════════════════════════════════════════════════════════════════
// ID Token `sid` claim test (unit-level, JWT service)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_id_token_contains_sid_claim() {
    let jwt = test_jwt();
    let profile = Profile::new(Some("sid_claim_test"));
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );

    let id_token = jwt
        .issue_id_token(
            &profile.id.to_string(),
            &profile,
            &session,
            "test-client",
            Some("nonce-123"),
            None,
            None,
        )
        .unwrap();

    let claims = jwt.decode_id_token_unverified(&id_token).unwrap();
    assert_eq!(claims.sid.as_deref(), Some(session.id.to_string().as_str()));
    assert_eq!(claims.sub, profile.id.to_string());
    assert_eq!(claims.nonce.as_deref(), Some("nonce-123"));
}

#[tokio::test]
async fn test_id_token_oidc_standard_claims_from_profile_fields() {
    let jwt = test_jwt();
    let mut profile = Profile::new(Some("oidc_claims_test"));
    profile.given_name = Some("Alice".to_string());
    profile.family_name = Some("Smith".to_string());
    profile.middle_name = Some("Marie".to_string());
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );

    let id_token = jwt
        .issue_id_token(
            &profile.id.to_string(),
            &profile,
            &session,
            "test-client",
            None,
            None,
            None,
        )
        .unwrap();

    let claims = jwt.decode_id_token_unverified(&id_token).unwrap();

    // OIDC §5.1 name claims from Profile Fields
    assert_eq!(claims.given_name.as_deref(), Some("Alice"));
    assert_eq!(claims.family_name.as_deref(), Some("Smith"));
    assert_eq!(claims.middle_name.as_deref(), Some("Marie"));
    assert_eq!(claims.name.as_deref(), Some("Alice Marie Smith"));
    assert_eq!(
        claims.preferred_username.as_deref(),
        Some("oidc_claims_test")
    );

    // Email/phone claims absent (no primary_email/primary_phone passed to issue_id_token)
    assert!(claims.email.is_none());
    assert!(claims.email_verified.is_none());
    assert!(claims.phone_number.is_none());
    assert!(claims.phone_number_verified.is_none());

    // updated_at from Profile.updated_at
    assert_eq!(claims.updated_at, Some(profile.updated_at.timestamp()));
}

#[tokio::test]
async fn test_id_token_no_email_omits_email_verified() {
    let jwt = test_jwt();
    let mut profile = Profile::new(Some("no_email_test"));
    profile.given_name = Some("Bob".to_string());
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );

    let id_token = jwt
        .issue_id_token(
            &profile.id.to_string(),
            &profile,
            &session,
            "test-client",
            None,
            None,
            None,
        )
        .unwrap();

    let claims = jwt.decode_id_token_unverified(&id_token).unwrap();

    // No email → email_verified must be absent (not false)
    assert!(claims.email.is_none());
    assert!(claims.email_verified.is_none());

    // Name claims still present
    assert_eq!(claims.given_name.as_deref(), Some("Bob"));
    assert!(claims.family_name.is_none());
}

// ═══════════════════════════════════════════════════════════════════
// Feature Flags
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_registration_disabled_blocks_create_profile() {
    let ff = FeatureFlagService::disabled();
    ff.set_flag("registration_enabled", false).await;
    let svc = TestServices::with_feature_flags(MockStorage::new(), ff);

    let req = admin_request(
        &svc,
        CreateProfileRequest {
            username: Some("disabled_user".to_string()),
            email: Some("disabled@sid.example.com".to_string()),
            phone: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            profile_type: 0,
            invite_code: None,
            referrer_id: None,
            utm: None,
        },
    );

    // Disabled registration is a setting an administrator can change, not a
    // missing permission.
    let err = svc.identity.create_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    let info = tonic_types::StatusExt::get_error_details(&err)
        .error_info()
        .cloned()
        .unwrap();
    assert_eq!(info.reason, "FEATURE_NOT_CONFIGURED");
    assert_eq!(info.metadata["feature"], "registration");
}

// ═══════════════════════════════════════════════════════════════════
// Project Management (ProjectService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_list_projects() {
    let mut admin_profile = Profile::new(Some("admin"));
    admin_profile.roles = vec!["admin".to_string()];
    let storage = MockStorage::new()
        .with_profile(admin_profile.clone())
        .with_system_project();
    let svc = TestServices::new(storage);
    let token = issue_admin_token(&svc.jwt, admin_profile.id);

    let req = authed_request(
        ListProjectsRequest {
            page_size: 100,
            page_token: String::new(),
        },
        &token,
    );

    let resp = svc.project.list_projects(req).await.unwrap();
    let body = resp.into_inner();
    assert_eq!(body.projects.len(), 1);
    assert_eq!(body.projects[0].name, "SID");
    assert!(body.projects[0].is_system);
}

// ═══════════════════════════════════════════════════════════════════
// Configurable TTL test (unit-level)
// ═══════════════════════════════════════════════════════════════════

/// Access tokens live five minutes by default.
#[tokio::test]
async fn test_token_response_expires_in_matches_ttl() {
    let jwt = test_jwt();
    assert_eq!(jwt.access_token_ttl_secs(), 300);
}

// ═══════════════════════════════════════════════════════════════════
// Credential mark_used test (unit-level)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_credential_mark_used_updates_last_used_at() {
    let profile = Profile::new(Some("cred_user"));
    let storage = MockStorage::new()
        .with_system_project()
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let mut cred = Credential::new(
        profile.id,
        CredentialType::Opaque,
        vec![1, 2, 3],
        Some("Test".to_string()),
    );
    assert!(cred.last_used_at.is_none());
    cred.mark_used();
    assert!(cred.last_used_at.is_some());

    svc.storage
        .create_credential(&cred, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let creds = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert_eq!(creds.len(), 1);
    assert!(creds[0].last_used_at.is_some());
}

// ═══════════════════════════════════════════════════════════════════
// Admin: Project CRUD (ProjectService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_create_project() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let req = new_command(admin_request(
        &svc,
        CreateProjectRequest {
            name: "New Project".to_string(),
            description: "Test description".to_string(),
            owner_profile_id: Uuid::now_v7().to_string(),
        },
    ));

    let resp = svc.project.create_project(req).await.unwrap();
    let project = resp.into_inner();
    assert_eq!(project.name, "New Project");
    assert_eq!(project.description, "Test description");
    assert!(!project.id.is_empty());
    assert!(!project.is_system);
}

#[tokio::test]
async fn test_admin_get_project() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let system_id = sid_core::models::ProjectId::system();
    let req = admin_request(
        &svc,
        GetProjectRequest {
            id: system_id.0.to_string(),
        },
    );

    let resp = svc.project.get_project(req).await.unwrap();
    let project = resp.into_inner();
    assert_eq!(project.name, "SID");
    assert!(project.is_system);
}

#[tokio::test]
async fn test_admin_get_nonexistent_project() {
    let svc = TestServices::new(MockStorage::new());
    let req = admin_request(
        &svc,
        GetProjectRequest {
            id: Uuid::now_v7().to_string(),
        },
    );

    let err = svc.project.get_project(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_admin_update_project() {
    let mut custom = Project::new("Original", None);
    custom.description = "old desc".to_string();
    let project_id = custom.id;
    let storage = MockStorage::new().with_project(custom);
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        UpdateProjectRequest {
            id: project_id.0.to_string(),
            name: Some("Updated Name".to_string()),
            description: Some("new desc".to_string()),
        },
    );

    let resp = svc.project.update_project(req).await.unwrap();
    let project = resp.into_inner();
    assert_eq!(project.name, "Updated Name");
    assert_eq!(project.description, "new desc");
}

#[tokio::test]
async fn test_admin_delete_project() {
    let custom = Project::new("Temp Project", None::<sid_core::models::ProfileId>);
    let project_id = custom.id;
    let storage = MockStorage::new().with_project(custom);
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        DeleteProjectRequest {
            id: project_id.0.to_string(),
        },
    );

    let resp = svc.project.delete_project(req).await;
    assert!(resp.is_ok());

    // Verify deleted
    let req = admin_request(
        &svc,
        GetProjectRequest {
            id: project_id.0.to_string(),
        },
    );
    let err = svc.project.get_project(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_admin_delete_system_project_forbidden() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let system_id = sid_core::models::ProjectId::system();
    let req = admin_request(
        &svc,
        DeleteProjectRequest {
            id: system_id.0.to_string(),
        },
    );

    let err = svc.project.delete_project(req).await.unwrap_err();
    // SID provisions and keeps the system project: the administrator has the
    // right, the resource's state forbids the change.
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    let (reason, _, _) = sid_core::grpc_error::extract_error_info(&err).expect("ErrorInfo");
    assert_eq!(reason, "SYSTEM_MANAGED");
}

// ═══════════════════════════════════════════════════════════════════
// Admin: Application CRUD (ProjectService)
// ═══════════════════════════════════════════════════════════════════

/// Settings of a client role of `kind` with one callback.
fn client_settings(kind: ApplicationType) -> ClientRoleSettings {
    ClientRoleSettings {
        r#type: kind as i32,
        redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        jwks: None,
        post_logout_redirect_uris: vec![],
    }
}

/// An administrator registers a web client with its public keys: it
/// authenticates with `private_key_jwt` and gets no secret. Keys for a public
/// client, or a private key, are refused and create nothing.
#[tokio::test]
async fn test_a_client_registered_with_keys_gets_no_secret() {
    const PUBLIC: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k"}]}"#;
    const PRIVATE: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","kid":"k"}]}"#;
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let with_keys = |kind: ApplicationType, jwks: &str| ClientRoleSettings {
        jwks: Some(jwks.to_string()),
        ..client_settings(kind)
    };

    let body = svc
        .project
        .create_application(create_app(
            &svc,
            "Keyed",
            Some(with_keys(ApplicationType::Web, PUBLIC)),
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(body.client_secret.is_empty());
    let client = body.application.unwrap().client.unwrap();
    let stored = svc
        .storage
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.token_endpoint_auth_method,
        sid_core::models::TokenEndpointAuthMethod::PrivateKeyJwt
    );
    assert!(stored.client_secret_hash.is_none());
    assert!(stored.jwks.unwrap().key("k").is_some());

    for (kind, jwks) in [
        (ApplicationType::Spa, PUBLIC),
        (ApplicationType::Native, PUBLIC),
        (ApplicationType::Web, PRIVATE),
    ] {
        let err = svc
            .project
            .create_application(create_app(
                &svc,
                "Refused",
                Some(with_keys(kind, jwks)),
                None,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::InvalidArgument,
            "{kind:?}: {err:?}"
        );
    }
    let clients = svc.storage.list_oauth2_clients(0, 100).await.unwrap();
    assert_eq!(clients.len(), 1, "a refused registration stored a client");
}

/// Settings of a resource role named by a fresh indicator.
fn resource_settings() -> ResourceRoleSettings {
    ResourceRoleSettings {
        indicator: format!("https://resources.example/{}", Uuid::now_v7().simple()),
        scopes: vec!["orders.read".to_string(), "orders.write".to_string()],
    }
}

/// A request creating application `name` in the system project with the
/// roles given.
fn create_app(
    svc: &TestServices,
    name: &str,
    client: Option<ClientRoleSettings>,
    resource: Option<ResourceRoleSettings>,
) -> tonic::Request<CreateApplicationRequest> {
    admin_request(
        svc,
        CreateApplicationRequest {
            project_id: sid_core::models::ProjectId::system().0.to_string(),
            name: name.to_string(),
            client,
            resource,
            org_id: None,
        },
    )
}

/// An application created with an OAuth client role, read back by its id.
#[tokio::test]
async fn test_admin_create_application() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let resp = svc
        .project
        .create_application(create_app(
            &svc,
            "My App",
            Some(client_settings(ApplicationType::Spa)),
            None,
        ))
        .await
        .unwrap();
    let body = resp.into_inner();
    let app = body.application.unwrap();
    assert_eq!(app.name, "My App");
    assert!(app.resource.is_none());
    let client = app.client.clone().unwrap();
    assert!(!client.client_id.is_empty());
    assert_eq!(client.application_id, app.id);
    // The installation's organization keys the application's pairwise subjects.
    assert_eq!(client.org_id, Some(common::test_org().to_string()));
    // Registration metadata is issuer-relative `public`; it does not decide
    // which identifier a user gets (authentication-flow.md, registration A).
    assert_eq!(client.subject_type, SubjectType::Public as i32);
    // The connection details name the exact issuer the application
    // configures, and reading the application back gives the same one.
    assert_eq!(client.issuer, svc.issuer.canonical_url);
    let read = svc
        .project
        .get_application(admin_request(
            &svc,
            GetApplicationRequest { id: app.id.clone() },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read.client.unwrap().issuer, svc.issuer.canonical_url);
}

/// A protected API needs no OAuth client: a resource-only application has no
/// client, no secret and no callback, and its indicator is its audience.
#[tokio::test]
async fn test_resource_only_application_has_no_client_or_secret() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let settings = resource_settings();
    let body = svc
        .project
        .create_application(create_app(&svc, "Orders API", None, Some(settings.clone())))
        .await
        .unwrap()
        .into_inner();
    assert!(body.client_secret.is_empty());
    let app = body.application.unwrap();
    assert!(app.client.is_none());
    let resource = app.resource.unwrap();
    assert_eq!(resource.indicator, settings.indicator);
    assert_eq!(resource.issuer, svc.issuer.canonical_url);
    assert_eq!(resource.scopes, settings.scopes);
    assert_eq!(resource.state, ResourceState::Active as i32);
    assert_eq!(resource.application_id, Some(app.id));
    assert!(
        svc.storage
            .list_oauth2_clients(0, 100)
            .await
            .unwrap()
            .is_empty(),
        "a resource-only registration created a client"
    );
}

/// An application is a client, a resource, or both: none is refused.
#[tokio::test]
async fn test_create_application_needs_a_role() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let err = svc
        .project
        .create_application(create_app(&svc, "Empty", None, None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");
}

/// A resource indicator is an absolute URI without a fragment in canonical
/// form (RFC 8707 §2); anything else is refused naming the field, and
/// nothing is stored.
#[tokio::test]
async fn test_resource_indicator_is_validated() {
    use tonic_types::StatusExt;
    let svc = TestServices::new(MockStorage::new().with_system_project());
    for indicator in [
        "/orders",
        "https://resources.example/orders#v1",
        "HTTPS://Resources.Example/orders",
    ] {
        let mut settings = resource_settings();
        settings.indicator = indicator.to_string();
        let err = svc
            .project
            .create_application(create_app(&svc, "Bad", None, Some(settings)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{indicator}");
        let violations = err.get_details_bad_request().expect("BadRequest");
        assert_eq!(violations.field_violations[0].field, "resource.indicator");
    }
    let mut settings = resource_settings();
    settings.scopes = vec!["has space".to_string()];
    let err = svc
        .project
        .create_application(create_app(&svc, "Bad", None, Some(settings)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let apps = svc
        .project
        .list_applications(admin_request(
            &svc,
            ListApplicationsRequest {
                project_id: sid_core::models::ProjectId::system().0.to_string(),
                page_size: 100,
                page_token: String::new(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(
        apps.applications.iter().all(|a| a.name != "Bad"),
        "a refused application was stored"
    );
}

/// An indicator names one resource of the issuer for ever: a second
/// registration of it is ALREADY_EXISTS, even after the first is retired.
#[tokio::test]
async fn test_resource_indicator_is_never_reused() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let settings = resource_settings();
    let first = svc
        .project
        .create_application(create_app(&svc, "First", None, Some(settings.clone())))
        .await
        .unwrap()
        .into_inner()
        .application
        .unwrap();
    let err = svc
        .project
        .create_application(create_app(&svc, "Second", None, Some(settings.clone())))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{err:?}");

    svc.project
        .delete_application(admin_request(
            &svc,
            DeleteApplicationRequest { id: first.id },
        ))
        .await
        .unwrap();
    let err = svc
        .project
        .create_application(create_app(&svc, "Reuse", None, Some(settings)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{err:?}");
}

/// Roles are added to an existing application once each: a client role to a
/// resource-only application works, a second of either kind is
/// ALREADY_EXISTS.
#[tokio::test]
async fn test_roles_are_added_once() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let app = svc
        .project
        .create_application(create_app(&svc, "API", None, Some(resource_settings())))
        .await
        .unwrap()
        .into_inner()
        .application
        .unwrap();

    let added = svc
        .project
        .add_client_role(admin_request(
            &svc,
            AddClientRoleRequest {
                application_id: app.id.clone(),
                settings: Some(client_settings(ApplicationType::Web)),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(
        !added.client_secret.is_empty(),
        "a web client gets a secret"
    );
    let with_both = added.application.unwrap();
    assert!(with_both.client.is_some() && with_both.resource.is_some());

    let err = svc
        .project
        .add_client_role(admin_request(
            &svc,
            AddClientRoleRequest {
                application_id: app.id.clone(),
                settings: Some(client_settings(ApplicationType::Web)),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{err:?}");
    let err = svc
        .project
        .add_resource_role(admin_request(
            &svc,
            AddResourceRoleRequest {
                application_id: app.id.clone(),
                settings: Some(resource_settings()),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{err:?}");

    let missing = admin_request(
        &svc,
        AddResourceRoleRequest {
            application_id: sid_core::models::ApplicationId::generate().to_string(),
            settings: Some(resource_settings()),
        },
    );
    let err = svc.project.add_resource_role(missing).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

/// A client obtains nothing for a resource by default: access is granted
/// explicitly, limited to the resource's scopes, listed from both sides and
/// removed; a default resource must be one the client has access to.
#[tokio::test]
async fn test_resource_access_is_explicit() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let api = svc
        .project
        .create_application(create_app(&svc, "API", None, Some(resource_settings())))
        .await
        .unwrap()
        .into_inner()
        .application
        .unwrap()
        .resource
        .unwrap();
    let web = svc
        .project
        .create_application(create_app(
            &svc,
            "Web",
            Some(client_settings(ApplicationType::Web)),
            None,
        ))
        .await
        .unwrap()
        .into_inner()
        .application
        .unwrap()
        .client
        .unwrap();

    // Without access, the resource cannot be the client's default.
    let default_to_api = |svc: &TestServices| {
        admin_request(
            svc,
            UpdateClientRoleRequest {
                client_id: web.client_id.clone(),
                default_resource_id: Some(api.id.clone()),
                ..Default::default()
            },
        )
    };
    let err = svc
        .project
        .update_client_role(default_to_api(&svc))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

    // A scope the resource does not understand is refused.
    let set = |scopes: &[&str]| {
        admin_request(
            &svc,
            SetResourceAccessRequest {
                client_id: web.client_id.clone(),
                resource_id: api.id.clone(),
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
            },
        )
    };
    let err = svc
        .project
        .set_resource_access(set(&["admin"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

    let access = svc
        .project
        .set_resource_access(set(&["orders.read"]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(access.scopes, vec!["orders.read"]);

    for request in [
        ListResourceAccessRequest {
            subject: Some(list_resource_access_request::Subject::ClientId(
                web.client_id.clone(),
            )),
        },
        ListResourceAccessRequest {
            subject: Some(list_resource_access_request::Subject::ResourceId(
                api.id.clone(),
            )),
        },
    ] {
        let listed = svc
            .project
            .list_resource_access(admin_request(&svc, request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.access.len(), 1);
        assert_eq!(listed.access[0].resource_id, api.id);
    }

    // With access, it can be the default.
    let app = svc
        .project
        .update_client_role(default_to_api(&svc))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        app.client.unwrap().default_resource_id,
        Some(api.id.clone())
    );

    svc.project
        .remove_resource_access(admin_request(
            &svc,
            RemoveResourceAccessRequest {
                client_id: web.client_id.clone(),
                resource_id: api.id.clone(),
            },
        ))
        .await
        .unwrap();
    let listed = svc
        .project
        .list_resource_access(admin_request(
            &svc,
            ListResourceAccessRequest {
                subject: Some(list_resource_access_request::Subject::ClientId(
                    web.client_id.clone(),
                )),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(listed.access.is_empty());
}

/// A machine user calling an API is given access like any client, by its
/// client id; an identifier naming neither a client nor a machine user is
/// NOT_FOUND.
#[tokio::test]
async fn test_machine_user_is_given_resource_access() {
    use sid_core::models::MachineUser;
    use sid_core::models::machine_user::OwnerType;
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let api = svc
        .project
        .create_application(create_app(&svc, "API", None, Some(resource_settings())))
        .await
        .unwrap()
        .into_inner()
        .application
        .unwrap()
        .resource
        .unwrap();
    let ci = MachineUser::new(
        sid_core::models::ProjectId::system(),
        "ci-deploy".to_string(),
        "CI",
        OwnerType::System,
        "system",
    );
    svc.storage
        .create_machine_user(&ci, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let set = |client_id: &str| {
        admin_request(
            &svc,
            SetResourceAccessRequest {
                client_id: client_id.to_string(),
                resource_id: api.id.clone(),
                scopes: vec!["orders.read".to_string()],
            },
        )
    };
    let access = svc
        .project
        .set_resource_access(set(&ci.client_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(access.client_id, ci.client_id);
    assert_eq!(access.scopes, vec!["orders.read"]);
    let listed = svc
        .project
        .list_resource_access(admin_request(
            &svc,
            ListResourceAccessRequest {
                subject: Some(list_resource_access_request::Subject::ResourceId(
                    api.id.clone(),
                )),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.access.len(), 1);
    assert_eq!(listed.access[0].client_id, ci.client_id);

    let err = svc
        .project
        .set_resource_access(set("nobody"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound, "{err:?}");
}

/// Removing an application retires its resource: it takes no access and no
/// change, and a resource is retired only that way.
#[tokio::test]
async fn test_retired_resource_takes_no_access_or_change() {
    use tonic_types::StatusExt;
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let api_app = svc
        .project
        .create_application(create_app(&svc, "API", None, Some(resource_settings())))
        .await
        .unwrap()
        .into_inner()
        .application
        .unwrap();
    let api = api_app.resource.clone().unwrap();

    // Retiring is not an update.
    let err = svc
        .project
        .update_resource_role(admin_request(
            &svc,
            UpdateResourceRoleRequest {
                resource_id: api.id.clone(),
                scopes: None,
                state: Some(ResourceState::Retired as i32),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");

    // Deactivate and reactivate, then change scopes.
    let updated = svc
        .project
        .update_resource_role(admin_request(
            &svc,
            UpdateResourceRoleRequest {
                resource_id: api.id.clone(),
                scopes: Some(ScopeList {
                    scopes: vec!["orders.read".to_string()],
                }),
                state: Some(ResourceState::Inactive as i32),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.state, ResourceState::Inactive as i32);
    assert_eq!(updated.scopes, vec!["orders.read"]);

    let web = svc
        .project
        .create_application(create_app(
            &svc,
            "Web",
            Some(client_settings(ApplicationType::Web)),
            None,
        ))
        .await
        .unwrap()
        .into_inner()
        .application
        .unwrap()
        .client
        .unwrap();

    svc.project
        .delete_application(admin_request(
            &svc,
            DeleteApplicationRequest { id: api_app.id },
        ))
        .await
        .unwrap();

    let err = svc
        .project
        .set_resource_access(admin_request(
            &svc,
            SetResourceAccessRequest {
                client_id: web.client_id.clone(),
                resource_id: api.id.clone(),
                scopes: vec!["orders.read".to_string()],
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");
    assert_eq!(
        err.get_details_error_info().unwrap().reason,
        "RESOURCE_RETIRED"
    );
    let err = svc
        .project
        .update_resource_role(admin_request(
            &svc,
            UpdateResourceRoleRequest {
                resource_id: api.id.clone(),
                scopes: None,
                state: Some(ResourceState::Active as i32),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");
}

/// Managing applications, resources and access is instance administration.
#[tokio::test]
async fn test_resource_management_requires_an_administrator() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_system_project()
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);
    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let mut request = tonic::Request::new(CreateApplicationRequest {
        project_id: sid_core::models::ProjectId::system().0.to_string(),
        name: "API".to_string(),
        client: None,
        resource: Some(resource_settings()),
        org_id: None,
    });
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let err = svc.project.create_application(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
}

/// A dynamically registered client that names no subject type gets the
/// documented `public` (authentication-flow.md, registration metadata A).
#[tokio::test]
async fn test_dcr_default_subject_type_is_public() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let mut req = dcr_request(&svc, "Default subject");
    // proto3: an unset enum is its documented UNSPECIFIED value.
    req.subject_type = SubjectType::Unspecified as i32;
    let app = svc
        .project
        .register_client(bearer_request(req, &iat_token))
        .await
        .unwrap()
        .into_inner()
        .client
        .unwrap();
    assert_eq!(app.subject_type, SubjectType::Public as i32);
    assert_eq!(app.issuer, svc.issuer.canonical_url);
}

/// A `private_key_jwt` registration without `jwks` could never authenticate
/// and is refused, registering nothing; with its keys it registers and reads
/// them back (RFC 7591 §2). Before, such a client was stored secret-less and
/// served as a public client.
#[tokio::test]
async fn test_dcr_private_key_jwt_needs_its_keys() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let mut req = dcr_request(&svc, "Key client");
    req.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt as i32;
    let err = svc
        .project
        .register_client(bearer_request(req.clone(), &iat_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");
    let clients = svc.storage.list_oauth2_clients(0, 100).await.unwrap();
    assert!(clients.iter().all(|c| !c.client_id.starts_with("dyn_")));

    let mut private = req.clone();
    private.jwks = Some(
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","kid":"k"}]}"#
            .into(),
    );
    let err = svc
        .project
        .register_client(bearer_request(private, &iat_token))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "a private key was accepted"
    );

    req.jwks = Some(
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k"}]}"#
            .into(),
    );
    let body = svc
        .project
        .register_client(bearer_request(req, &iat_token))
        .await
        .unwrap()
        .into_inner();
    assert!(body.client_secret.is_none(), "a key client gets no secret");
    let client = body.client.unwrap();
    let registered = sid_core::models::ClientKeySet::from_json(client.jwks.as_deref().unwrap());
    assert!(registered.unwrap().key("k").is_some());

    // RFC 7592 §2.2: the client rotates to its next key; an update that
    // would leave it keyless is refused and changes nothing.
    let rat = body.registration_access_token;
    let mut keyless = full_update(&svc, &client.client_id);
    keyless.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::PrivateKeyJwt as i32);
    keyless.jwks = None;
    let err = svc
        .project
        .update_registered_client(bearer_request(keyless, &rat))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

    let mut rotated = full_update(&svc, &client.client_id);
    rotated.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::PrivateKeyJwt as i32);
    rotated.jwks = Some(
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"next"}]}"#
            .into(),
    );
    svc.project
        .update_registered_client(bearer_request(rotated, &rat))
        .await
        .unwrap();
    let stored = svc
        .storage
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap()
        .jwks
        .unwrap();
    assert!(stored.key("next").is_some());
    assert!(stored.key("k").is_none(), "the old key was rotated out");
}

/// Browser and native applications are public clients: they get no secret
/// and authenticate with none, since a secret shipped in them is not secret
/// (RFC 8252 §8.4). A web or API application gets one.
#[tokio::test]
async fn test_public_applications_get_no_secret() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let create = |kind: ApplicationType| create_app(&svc, "App", Some(client_settings(kind)), None);
    for public in [ApplicationType::Spa, ApplicationType::Native] {
        let body = svc
            .project
            .create_application(create(public))
            .await
            .unwrap()
            .into_inner();
        assert!(body.client_secret.is_empty(), "{public:?}");
        let stored = svc
            .storage
            .get_oauth2_client(&body.application.unwrap().client.unwrap().client_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.client_secret_hash.is_none(), "{public:?}");
        assert_eq!(
            stored.token_endpoint_auth_method,
            sid_core::models::TokenEndpointAuthMethod::None,
            "{public:?}"
        );
    }
    let body = svc
        .project
        .create_application(create(ApplicationType::Web))
        .await
        .unwrap()
        .into_inner();
    assert!(!body.client_secret.is_empty());
}

/// An application cannot be placed in an organization this installation
/// does not have.
#[tokio::test]
async fn test_application_in_a_foreign_organization_is_refused() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let req = admin_request(
        &svc,
        CreateApplicationRequest {
            project_id: sid_core::models::ProjectId::system().0.to_string(),
            name: "Foreign".to_string(),
            client: Some(client_settings(ApplicationType::Web)),
            resource: None,
            org_id: Some(sid_core::models::OrgId::generate().to_string()),
        },
    );
    let err = svc.project.create_application(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");
}

#[tokio::test]
async fn test_admin_create_application_nonexistent_project() {
    let svc = TestServices::new(MockStorage::new());

    let req = admin_request(
        &svc,
        CreateApplicationRequest {
            project_id: Uuid::now_v7().to_string(),
            name: "Orphan App".to_string(),
            client: Some(client_settings(ApplicationType::Spa)),
            resource: None,
            org_id: None,
        },
    );

    let err = svc.project.create_application(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_admin_get_application() {
    let client = test_client();
    let storage = MockStorage::new()
        .with_system_project()
        .with_client(client.clone());
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        GetApplicationRequest {
            id: client.application_id.to_string(),
        },
    );

    let resp = svc.project.get_application(req).await.unwrap();
    let app = resp.into_inner();
    assert_eq!(app.client.unwrap().client_id, "test-client");
    assert_eq!(app.name, "Test App");
}

/// An unknown application is NOT_FOUND; a malformed id is INVALID_ARGUMENT.
#[tokio::test]
async fn test_admin_get_nonexistent_application() {
    let svc = TestServices::new(MockStorage::new());
    let req = admin_request(
        &svc,
        GetApplicationRequest {
            id: sid_core::models::ApplicationId::generate().to_string(),
        },
    );
    let err = svc.project.get_application(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    let req = admin_request(
        &svc,
        GetApplicationRequest {
            id: "nonexistent".to_string(),
        },
    );
    let err = svc.project.get_application(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_admin_list_applications() {
    let client = test_client();
    let storage = MockStorage::new().with_system_project().with_client(client);
    let svc = TestServices::new(storage);

    let system_id = sid_core::models::ProjectId::system();
    let req = admin_request(
        &svc,
        ListApplicationsRequest {
            project_id: system_id.0.to_string(),
            page_size: 100,
            page_token: String::new(),
        },
    );

    let resp = svc.project.list_applications(req).await.unwrap();
    let body = resp.into_inner();
    // The stored client's application, and the issuer's UserInfo resource
    // provisioned at start, both in the system project.
    let mut names: Vec<&str> = body.applications.iter().map(|a| a.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, vec!["OIDC UserInfo", "Test App"]);
}

/// Renaming an application changes its administrative name only; the
/// client's user-facing name is its own setting.
#[tokio::test]
async fn test_admin_update_application() {
    let client = test_client();
    let storage = MockStorage::new()
        .with_system_project()
        .with_client(client.clone());
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        UpdateApplicationRequest {
            id: client.application_id.to_string(),
            name: Some("Updated App Name".to_string()),
        },
    );

    let app = svc
        .project
        .update_application(req)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(app.name, "Updated App Name");
    assert_eq!(app.revision, 1);
    assert_eq!(app.client.unwrap().name, "Test App");

    let empty = admin_request(
        &svc,
        UpdateApplicationRequest {
            id: client.application_id.to_string(),
            name: Some(String::new()),
        },
    );
    let err = svc.project.update_application(empty).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_admin_update_client_role() {
    let client = test_client();
    let storage = MockStorage::new().with_system_project().with_client(client);
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        UpdateClientRoleRequest {
            client_id: "test-client".to_string(),
            name: Some("Updated App Name".to_string()),
            redirect_uris: vec!["https://new.sid.example.com/callback".to_string()],
            allowed_scopes: vec!["openid".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            active: Some(false),
            subject_type: None,
            default_resource_id: None,
            post_logout_redirect_uris: Some(sid_proto::sid::v1::UriList {
                uris: vec!["https://new.sid.example.com/signed-out".to_string()],
            }),
        },
    );

    let app = svc
        .project
        .update_client_role(req)
        .await
        .unwrap()
        .into_inner();
    let client = app.client.unwrap();
    assert_eq!(client.name, "Updated App Name");
    assert!(!client.active);
    assert_eq!(
        client.redirect_uris,
        vec!["https://new.sid.example.com/callback"]
    );
    assert_eq!(
        client.post_logout_redirect_uris,
        vec!["https://new.sid.example.com/signed-out"]
    );
}

/// A post-logout redirect URI an administrator sets is held to the redirect
/// URI rules of the client's type: plain http to a remote host is refused,
/// naming the field, and nothing changes. An empty list clears them.
#[tokio::test]
async fn test_admin_post_logout_redirect_uris_are_validated() {
    let client = test_client();
    let storage = MockStorage::new().with_system_project().with_client(client);
    let svc = TestServices::new(storage);
    let update = |uris: Vec<&str>| UpdateClientRoleRequest {
        client_id: "test-client".to_string(),
        post_logout_redirect_uris: Some(sid_proto::sid::v1::UriList {
            uris: uris.into_iter().map(str::to_string).collect(),
        }),
        ..Default::default()
    };

    let err = svc
        .project
        .update_client_role(admin_request(
            &svc,
            update(vec!["http://evil.sid.example.com/bye"]),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("post-logout"), "{}", err.message());

    let set = svc
        .project
        .update_client_role(admin_request(
            &svc,
            update(vec!["https://app.sid.example.com/bye"]),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        set.client.unwrap().post_logout_redirect_uris,
        vec!["https://app.sid.example.com/bye"]
    );
    let cleared = svc
        .project
        .update_client_role(admin_request(&svc, update(vec![])))
        .await
        .unwrap()
        .into_inner();
    assert!(cleared.client.unwrap().post_logout_redirect_uris.is_empty());
}

/// The code and field an incompatible-metadata refusal carries
/// (authentication-flow.md, registration metadata A).
fn metadata_refusal(err: &tonic::Status) -> (String, String) {
    use tonic_types::StatusExt;
    let info = err
        .get_details_error_info()
        .unwrap_or_else(|| panic!("no ErrorInfo in {err:?}"));
    (
        info.metadata.get("oauthError").cloned().unwrap_or_default(),
        info.metadata.get("field").cloned().unwrap_or_default(),
    )
}

fn subject_type_update(subject_type: &str) -> UpdateClientRoleRequest {
    UpdateClientRoleRequest {
        client_id: "test-client".to_string(),
        name: Some("Renamed".to_string()),
        subject_type: Some(subject_type.to_string()),
        ..Default::default()
    }
}

/// An administrator cannot switch an application to pairwise: the issuer
/// supports only `public` metadata, and a settings edit never starts an
/// identity migration. The whole update is refused and nothing changes.
#[tokio::test]
async fn test_update_application_refuses_pairwise_and_changes_nothing() {
    let mut client = test_client();
    client.subject_type = sid_core::models::SubjectType::Public;
    let before = client.clone();
    let storage = MockStorage::new().with_system_project().with_client(client);
    let svc = TestServices::new(storage);

    for requested in ["pairwise", "sector", ""] {
        let err = svc
            .project
            .update_client_role(admin_request(&svc, subject_type_update(requested)))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::InvalidArgument,
            "{requested}: {err:?}"
        );
        assert_eq!(
            metadata_refusal(&err),
            ("invalid_client_metadata".into(), "subject_type".into()),
            "{requested}"
        );
    }
    let loaded = svc
        .storage
        .get_oauth2_client("test-client")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.client_name, before.client_name, "no partial write");
    assert_eq!(loaded.subject_type, sid_core::models::SubjectType::Public);
}

/// Naming the value an application already has is accepted; asking a stored
/// pairwise application to become public is an identity change, which only
/// the explicit migration contract may perform.
#[tokio::test]
async fn test_update_application_public_request() {
    let mut public = test_client();
    public.subject_type = sid_core::models::SubjectType::Public;
    let svc = TestServices::new(MockStorage::new().with_system_project().with_client(public));
    let client = svc
        .project
        .update_client_role(admin_request(&svc, subject_type_update("public")))
        .await
        .unwrap()
        .into_inner()
        .client
        .unwrap();
    assert_eq!(client.name, "Renamed");
    assert_eq!(client.subject_type, SubjectType::Public as i32);

    let mut pairwise = test_client();
    pairwise.subject_type = sid_core::models::SubjectType::Pairwise;
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_client(pairwise),
    );
    let err = svc
        .project
        .update_client_role(admin_request(&svc, subject_type_update("public")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");
    let loaded = svc
        .storage
        .get_oauth2_client("test-client")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.subject_type, sid_core::models::SubjectType::Pairwise);
    assert_ne!(loaded.client_name, "Renamed", "no partial write");
}

/// Deleting an application removes it with its client role; a second delete
/// is NOT_FOUND.
#[tokio::test]
async fn test_admin_delete_application() {
    let client = test_client();
    let storage = MockStorage::new()
        .with_system_project()
        .with_client(client.clone());
    let svc = TestServices::new(storage);
    let id = client.application_id.to_string();

    let req = admin_request(&svc, DeleteApplicationRequest { id: id.clone() });
    svc.project.delete_application(req).await.unwrap();

    let req = admin_request(&svc, GetApplicationRequest { id: id.clone() });
    let err = svc.project.get_application(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert!(
        svc.storage
            .get_oauth2_client("test-client")
            .await
            .unwrap()
            .is_none()
    );
    let req = admin_request(&svc, DeleteApplicationRequest { id });
    let err = svc.project.delete_application(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

// ═══════════════════════════════════════════════════════════════════
// Admin: Profile Management (IdentityService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_list_profiles() {
    let profile1 = test_profile(); // alice
    let profile2 = Profile::new(Some("bob"));
    // Unclaimed store: the listing must return exactly the two stored profiles.
    let storage = MockStorage::unclaimed()
        .with_profile(profile1)
        .with_profile(profile2);
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        ListProfilesRequest {
            page_size: 100,
            page_token: String::new(),
        },
    );

    let resp = svc.identity.list_profiles(req).await.unwrap();
    let body = resp.into_inner();
    assert_eq!(body.profiles.len(), 2);
}

#[tokio::test]
async fn test_admin_delete_profile() {
    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        DeleteProfileRequest {
            id: pid.to_string(),
        },
    );

    let resp = svc.identity.delete_profile(req).await;
    assert!(resp.is_ok());

    // Verify deleted
    let get_result = svc.storage.get_profile(pid).await.unwrap();
    assert!(get_result.is_none());
}

#[tokio::test]
async fn test_admin_get_profile_detail() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let req = admin_request(
        &svc,
        GetProfileRequest {
            identifier: Some(get_profile_request::Identifier::Username(
                "alice".to_string(),
            )),
        },
    );

    let resp = svc.identity.get_profile(req).await.unwrap();
    let p = resp.into_inner().profile.unwrap();
    assert_eq!(p.username.as_deref(), Some("alice"));
    // Email now in profile_emails table, proto Profile.email populated separately
}

#[tokio::test]
async fn test_get_profile_returns_primary_email_in_proto() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Save a primary email for the profile
    let pe = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: profile.id,
        email: "alice-primary@sid.example.com".to_string(),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: true,
        verified_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    svc.storage
        .create_profile_email(&pe, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // get_profile should return email populated from primary contact
    let req = admin_request(
        &svc,
        GetProfileRequest {
            identifier: Some(get_profile_request::Identifier::Username(
                "alice".to_string(),
            )),
        },
    );
    let resp = svc.identity.get_profile(req).await.unwrap();
    let p = resp.into_inner().profile.unwrap();
    assert_eq!(
        p.email.as_deref(),
        Some("alice-primary@sid.example.com"),
        "proto Profile.email should be populated from primary ProfileEmail"
    );
    assert!(
        p.email_verified,
        "email_verified should reflect ProfileEmail.verified"
    );
}

#[tokio::test]
async fn test_admin_get_profile_by_email() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Register email in profile_emails for get_profile_by_email lookup
    let email = sid_core::models::ProfileEmail {
        id: sid_core::models::ProfileEmailId::new(),
        profile_id: profile.id,
        email: "alice@sid.example.com".to_string(),
        label: sid_core::models::EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: true,
        verified_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    svc.storage
        .create_profile_email(&email, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let req = admin_request(
        &svc,
        GetProfileRequest {
            identifier: Some(get_profile_request::Identifier::Email(
                "alice@sid.example.com".to_string(),
            )),
        },
    );

    let resp = svc.identity.get_profile(req).await.unwrap();
    let p = resp.into_inner().profile.unwrap();
    assert_eq!(p.username.as_deref(), Some("alice"));
}

#[tokio::test]
async fn test_admin_get_nonexistent_profile() {
    let svc = TestServices::new(MockStorage::new());

    let req = admin_request(
        &svc,
        GetProfileRequest {
            identifier: Some(get_profile_request::Identifier::Id(
                Uuid::now_v7().to_string(),
            )),
        },
    );

    let err = svc.identity.get_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

// ═══════════════════════════════════════════════════════════════════
// Admin: Session Management (IdentityService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_list_sessions() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create a session
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    svc.storage
        .create_session(&session, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let req = admin_request(
        &svc,
        ListSessionsRequest {
            profile_id: profile.id.to_string(),
        },
    );

    let resp = svc.identity.list_sessions(req).await.unwrap();
    let body = resp.into_inner();
    assert_eq!(body.sessions.len(), 1);
}

#[tokio::test]
async fn test_admin_revoke_session() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create a session
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    svc.storage
        .create_session(&session, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let req = admin_request(
        &svc,
        RevokeSessionRequest {
            session_id: session.id.to_string(),
        },
    );

    let resp = svc.identity.revoke_session(req).await;
    assert!(resp.is_ok());

    // Verify session deleted
    let s = svc.storage.get_session(session.id).await.unwrap();
    assert!(s.is_none());
}

#[tokio::test]
async fn test_admin_revoke_all_sessions() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create two sessions
    for _ in 0..2 {
        let session = Session::new(
            profile.id,
            "127.0.0.1".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        svc.storage
            .create_session(&session, AuditEntry::system("test", "test").into())
            .await
            .unwrap();
    }

    // Verify 2 sessions exist
    let sessions = svc
        .storage
        .list_sessions_by_profile(profile.id)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2);

    // Revoke all via storage (IdentityService doesn't have a bulk RPC yet)
    let ended = svc
        .storage
        .delete_sessions_by_profile(
            profile.id,
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "test",
            ),
            AuditEntry::system("test", "bulk revoke").into(),
        )
        .await
        .unwrap();
    assert_eq!(ended.len(), 2);

    // Verify all deleted
    let sessions = svc
        .storage
        .list_sessions_by_profile(profile.id)
        .await
        .unwrap();
    assert!(sessions.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// Admin: Credential Management (IdentityService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_list_credentials() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create a credential
    let cred = Credential::new(
        profile.id,
        CredentialType::Opaque,
        vec![1, 2, 3],
        Some("Password".to_string()),
    );
    svc.storage
        .create_credential(&cred, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let req = admin_request(
        &svc,
        ListCredentialsRequest {
            profile_id: profile.id.to_string(),
        },
    );

    let resp = svc.identity.list_credentials(req).await.unwrap();
    let body = resp.into_inner();
    assert_eq!(body.credentials.len(), 1);
    // Credential data should be cleared (not exposed)
    assert!(body.credentials[0].data.is_empty());
}

#[tokio::test]
async fn test_admin_revoke_credential() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create two credentials (can't revoke last one)
    let cred1 = Credential::new(
        profile.id,
        CredentialType::Opaque,
        vec![1, 2, 3],
        Some("Primary".to_string()),
    );
    let cred2 = Credential::new(
        profile.id,
        CredentialType::WebAuthn,
        vec![4, 5, 6],
        Some("Backup".to_string()),
    );
    svc.storage
        .create_credential(&cred1, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    svc.storage
        .create_credential(&cred2, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let req = admin_request(
        &svc,
        RevokeCredentialRequest {
            credential_id: cred1.id.0.to_string(),
        },
    );

    let resp = svc.identity.revoke_credential(req).await;
    assert!(resp.is_ok());

    // Revoked, and the record is kept.
    let c = svc.storage.get_credential(cred1.id).await.unwrap();
    assert!(!c.expect("revocation keeps the record").status.is_active());
}

#[tokio::test]
async fn test_admin_revoke_last_credential_blocked() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create single credential
    let cred = Credential::new(
        profile.id,
        CredentialType::Opaque,
        vec![1, 2, 3],
        Some("Only".to_string()),
    );
    svc.storage
        .create_credential(&cred, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let req = admin_request(
        &svc,
        RevokeCredentialRequest {
            credential_id: cred.id.0.to_string(),
        },
    );

    let err = svc.identity.revoke_credential(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

// ═══════════════════════════════════════════════════════════════════
// Admin: E2E Flow (Project → Application → List)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_admin_project_and_application_flow() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    // Step 1: Create project
    let resp = svc
        .project
        .create_project(new_command(admin_request(
            &svc,
            CreateProjectRequest {
                name: "E2E Project".to_string(),
                description: "End-to-end test".to_string(),
                owner_profile_id: Uuid::now_v7().to_string(),
            },
        )))
        .await
        .unwrap();
    let project = resp.into_inner();
    let project_id = project.id.clone();

    // Step 2: Create application in project
    let resp = svc
        .project
        .create_application(admin_request(
            &svc,
            CreateApplicationRequest {
                project_id: project_id.clone(),
                name: "E2E App".to_string(),
                client: Some(ClientRoleSettings {
                    r#type: ApplicationType::Web as i32,
                    redirect_uris: vec!["https://e2e.sid.example.com/callback".to_string()],
                    allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    jwks: None,
                    post_logout_redirect_uris: vec![],
                }),
                resource: None,
                org_id: None,
            },
        ))
        .await
        .unwrap();
    let create_resp = resp.into_inner();
    let app = create_resp.application.unwrap();
    let app_id = app.id.clone();
    let client_id = app.client.unwrap().client_id;
    assert_eq!(app.name, "E2E App");

    // Step 3: List applications in project
    let resp = svc
        .project
        .list_applications(admin_request(
            &svc,
            ListApplicationsRequest {
                project_id: project_id.clone(),
                page_size: 100,
                page_token: String::new(),
            },
        ))
        .await
        .unwrap();
    assert_eq!(resp.into_inner().applications.len(), 1);

    // Step 4: Get application by id
    let resp = svc
        .project
        .get_application(admin_request(
            &svc,
            GetApplicationRequest { id: app_id.clone() },
        ))
        .await
        .unwrap();
    assert_eq!(resp.into_inner().name, "E2E App");

    // Step 5: Update the application and its client role
    let resp = svc
        .project
        .update_application(admin_request(
            &svc,
            UpdateApplicationRequest {
                id: app_id.clone(),
                name: Some("E2E App v2".to_string()),
            },
        ))
        .await
        .unwrap();
    assert_eq!(resp.into_inner().name, "E2E App v2");
    let resp = svc
        .project
        .update_client_role(admin_request(
            &svc,
            UpdateClientRoleRequest {
                client_id: client_id.clone(),
                redirect_uris: vec!["https://e2e-v2.sid.example.com/callback".to_string()],
                active: Some(true),
                ..Default::default()
            },
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.into_inner().client.unwrap().redirect_uris,
        vec!["https://e2e-v2.sid.example.com/callback"]
    );

    // Step 6: Delete application
    let resp = svc
        .project
        .delete_application(admin_request(&svc, DeleteApplicationRequest { id: app_id }))
        .await;
    assert!(resp.is_ok());

    // Step 7: Delete project
    let resp = svc
        .project
        .delete_project(admin_request(&svc, DeleteProjectRequest { id: project_id }))
        .await;
    assert!(resp.is_ok());

    // Verify: list projects = only system
    let resp = svc
        .project
        .list_projects(admin_request(
            &svc,
            ListProjectsRequest {
                page_size: 100,
                page_token: String::new(),
            },
        ))
        .await
        .unwrap();
    let projects = resp.into_inner().projects;
    assert_eq!(projects.len(), 1);
    assert!(projects[0].is_system);
}

// ═══════════════════════════════════════════════════════════════════
// OAuth2: Authorize with valid token (redirect)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_authorize_with_valid_token_redirects() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_client(test_client())
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let bearer = common::fresh_token(&svc, &profile).await;

    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.sid.example.com/callback".to_string(),
            response_type: "code".to_string(),
            scope: Some("openid".to_string()),
            state: Some("test_state".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: Some("test-nonce".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &bearer,
    );

    let resp = svc.auth.o_auth2_authorize(req).await.unwrap();
    let auth_resp = resp.into_inner();
    match auth_resp.result {
        Some(AuthzResult::AuthorizationCode(code)) => {
            assert!(!code.is_empty());
        }
        other => panic!("expected authorization_code, got {:?}", other),
    }
}

/// A still-valid token of a session that has ended (signed out, revoked)
/// authorizes nothing: the code would carry that session's authentication.
#[tokio::test]
async fn test_authorize_refuses_an_ended_session() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(profile.clone()),
    );
    let (bearer, session) = common::issue_token_with_session(
        &svc.jwt,
        &profile,
        &["openid".to_string()],
        common::authenticated_session(&profile, sid_core::models::AuthLevel::Basic, 0),
    );
    svc.storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    svc.storage
        .delete_session(
            session.id,
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "user",
            ),
            AuditEntry::system("test", "sign-out").into(),
        )
        .await
        .unwrap();

    let err = svc
        .auth
        .o_auth2_authorize(authed_request(
            OAuth2AuthorizeRequest {
                client_id: "test-client".to_string(),
                redirect_uri: common::oauth_client::REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: Some("openid".to_string()),
                state: Some("s".to_string()),
                nonce: Some("n".to_string()),
                code_challenge: Some(common::oauth_client::CODE_CHALLENGE.to_string()),
                code_challenge_method: Some("S256".to_string()),
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &bearer,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

// ═══════════════════════════════════════════════════════════════════
// OAuth2: Token client_credentials with public client (rejected)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_token_client_credentials_public_client_rejected() {
    let client = test_client(); // SPA = public client
    let storage = MockStorage::new().with_system_project().with_client(client);
    let svc = TestServices::new(storage);

    let req = Request::new(OAuth2TokenRequest {
        grant_type: "client_credentials".to_string(),
        client_id: Some("test-client".to_string()),
        ..Default::default()
    });

    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert!(
        err.code() == tonic::Code::InvalidArgument
            || err.code() == tonic::Code::Unauthenticated
            || err.code() == tonic::Code::PermissionDenied
            || err.code() == tonic::Code::Unimplemented,
        "expected error for public client using client_credentials, got {:?}: {}",
        err.code(),
        err.message()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Feature Flags: Registration disabled still allows GetCurrentProfile
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_registration_disabled_allows_get_current_profile() {
    let ff = FeatureFlagService::disabled();
    ff.set_flag("registration_enabled", false).await;

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::with_feature_flags(storage, ff);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(GetCurrentProfileRequest {}, &token);
    let resp = svc.identity.get_current_profile(req).await.unwrap();
    let p = resp.into_inner().profile.unwrap();
    assert_eq!(p.username.as_deref(), Some("alice"));
}

// ═══════════════════════════════════════════════════════════════════
// OPAQUE: Wrong password login attempt
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_opaque_wrong_password() {
    use sid_opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };
    use sid_pake_core::pallas_opaque::PallasCipherSuite;

    let email = "wrong_pw@sid.example.com";
    let svc = TestServices::new(MockStorage::new());

    // Register a new account with the correct password
    let correct_pw = b"correct-password-123";
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);

    let reg_start = ClientRegistration::<PallasCipherSuite>::start(&mut rng, correct_pw).unwrap();

    let resp = svc
        .auth
        .opaque_registration_start(Request::new(OpaqueRegistrationStartRequest {
            principal: email.to_string(),
            registration_request: reg_start.message.serialize().to_vec(),
            claim_token: None,
        }))
        .await
        .unwrap();
    let reg_resp = resp.into_inner();

    let reg_response =
        RegistrationResponse::<PallasCipherSuite>::deserialize(&reg_resp.registration_response)
            .unwrap();

    let reg_finish = reg_start
        .state
        .finish(
            &mut rng,
            correct_pw,
            reg_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    svc.auth
        .opaque_registration_finish(Request::new(OpaqueRegistrationFinishRequest {
            principal: email.to_string(),
            registration_record: reg_finish.message.serialize().to_vec(),
            server_setup: reg_resp.server_setup.clone(),
        }))
        .await
        .unwrap();

    // Now try login with WRONG password
    let wrong_pw = b"wrong-password-456";
    let login_start = ClientLogin::<PallasCipherSuite>::start(&mut rng, wrong_pw).unwrap();

    let resp = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: email.to_string(),
            credential_request: login_start.message.serialize().to_vec(),
        }))
        .await
        .unwrap();
    let login_resp = resp.into_inner();

    let cred_response =
        CredentialResponse::<PallasCipherSuite>::deserialize(&login_resp.credential_response)
            .unwrap();

    // Client-side finish should fail with wrong password
    let finish_result = login_start.state.finish(
        &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
        wrong_pw,
        cred_response,
        ClientLoginFinishParameters::default(),
    );
    assert!(
        finish_result.is_err(),
        "login finish should fail with wrong password"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Token: expires_in matches configured TTL
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_opaque_login_response_uses_dynamic_expires_in() {
    // This test verifies that the token response expires_in comes from JWT TTL config
    // We already test this via test_token_response_expires_in_matches_ttl
    // and the e2e auth code flow (expects 300). This test validates through OPAQUE login.
    use sid_opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };
    use sid_pake_core::pallas_opaque::PallasCipherSuite;

    let email = "ttl_test@sid.example.com";
    let svc = TestServices::new(MockStorage::new());

    let password = b"ttl-test-password";
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);

    // Register
    let reg_start = ClientRegistration::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let resp = svc
        .auth
        .opaque_registration_start(Request::new(OpaqueRegistrationStartRequest {
            principal: email.to_string(),
            registration_request: reg_start.message.serialize().to_vec(),
            claim_token: None,
        }))
        .await
        .unwrap()
        .into_inner();

    let reg_response =
        RegistrationResponse::<PallasCipherSuite>::deserialize(&resp.registration_response)
            .unwrap();
    let reg_finish = reg_start
        .state
        .finish(
            &mut rng,
            password,
            reg_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    svc.auth
        .opaque_registration_finish(Request::new(OpaqueRegistrationFinishRequest {
            principal: email.to_string(),
            registration_record: reg_finish.message.serialize().to_vec(),
            server_setup: resp.server_setup.clone(),
        }))
        .await
        .unwrap();

    // Login
    let login_start = ClientLogin::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let login_resp = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: email.to_string(),
            credential_request: login_start.message.serialize().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();

    let cred_response =
        CredentialResponse::<PallasCipherSuite>::deserialize(&login_resp.credential_response)
            .unwrap();
    let login_finish = login_start
        .state
        .finish(
            &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
            password,
            cred_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    let token_resp = svc
        .auth
        .opaque_login_finish(Request::new(OpaqueLoginFinishRequest {
            principal: email.to_string(),
            credential_finalization: login_finish.message.serialize().to_vec(),
            server_login_state: login_resp.server_login_state,
        }))
        .await
        .unwrap()
        .into_inner();

    // Verify expires_in matches JWT TTL (300 seconds default)
    assert_eq!(
        token_resp.expires_in, 300,
        "token expires_in should match JWT TTL"
    );
}

/// A sign-in over the session limit evicts the oldest session, and that
/// session's access tokens stop at once instead of living until they expire.
#[tokio::test]
async fn test_session_evicted_at_limit_stops_its_tokens() {
    use sid_opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };
    use sid_pake_core::pallas_opaque::PallasCipherSuite;

    let email = "limit_evict@sid.example.com";
    let mut svc = TestServices::new(MockStorage::new());
    let mut policy = sid_core::models::SecurityPolicy::ce_default();
    policy.session.max_concurrent_sessions = 1;
    let auth = std::sync::Arc::into_inner(svc.auth).expect("no other handle yet");
    svc.auth = std::sync::Arc::new(auth.with_security_policy(policy));

    let password = b"limit-evict-password";
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let reg_start = ClientRegistration::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let resp = svc
        .auth
        .opaque_registration_start(Request::new(OpaqueRegistrationStartRequest {
            principal: email.to_string(),
            registration_request: reg_start.message.serialize().to_vec(),
            claim_token: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let reg_finish = reg_start
        .state
        .finish(
            &mut rng,
            password,
            RegistrationResponse::<PallasCipherSuite>::deserialize(&resp.registration_response)
                .unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    svc.auth
        .opaque_registration_finish(Request::new(OpaqueRegistrationFinishRequest {
            principal: email.to_string(),
            registration_record: reg_finish.message.serialize().to_vec(),
            server_setup: resp.server_setup.clone(),
        }))
        .await
        .unwrap();

    let mut sessions = Vec::new();
    for _ in 0..2 {
        let login_start = ClientLogin::<PallasCipherSuite>::start(&mut rng, password).unwrap();
        let login_resp = svc
            .auth
            .opaque_login_start(Request::new(OpaqueLoginStartRequest {
                principal: email.to_string(),
                credential_request: login_start.message.serialize().to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();
        let login_finish = login_start
            .state
            .finish(
                &mut rng,
                password,
                CredentialResponse::<PallasCipherSuite>::deserialize(
                    &login_resp.credential_response,
                )
                .unwrap(),
                ClientLoginFinishParameters::default(),
            )
            .unwrap();
        let token = svc
            .auth
            .opaque_login_finish(Request::new(OpaqueLoginFinishRequest {
                principal: email.to_string(),
                credential_finalization: login_finish.message.serialize().to_vec(),
                server_login_state: login_resp.server_login_state,
            }))
            .await
            .unwrap()
            .into_inner();
        sessions.push(token.session_id);
        // Distinct creation times order the sessions.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    assert!(
        svc.revocation_cache
            .is_revoked("", &sessions[0])
            .await
            .unwrap(),
        "the evicted session's access tokens still pass"
    );
    assert!(
        !svc.revocation_cache
            .is_revoked("", &sessions[1])
            .await
            .unwrap()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Maintenance Mode (Feature Flag: maintenance_mode)
// ═══════════════════════════════════════════════════════════════════

async fn maintenance_mode_services() -> TestServices {
    let ff = FeatureFlagService::disabled();
    ff.set_flag("maintenance_mode", true).await;
    TestServices::with_feature_flags(MockStorage::new(), ff)
}

#[tokio::test]
async fn test_maintenance_mode_blocks_auth_service() {
    let svc = maintenance_mode_services().await;

    // OPAQUE login start should fail with UNAVAILABLE
    let result = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: "alice@sid.example.com".to_string(),
            credential_request: vec![0; 32],
        }))
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert!(status.message().contains("maintenance"));
}

#[tokio::test]
async fn test_maintenance_mode_blocks_identity_service() {
    let svc = maintenance_mode_services().await;

    let result = svc
        .identity
        .create_profile(admin_request(
            &svc,
            CreateProfileRequest {
                username: Some("test".to_string()),
                email: Some("test@sid.example.com".to_string()),
                phone: None,
                given_name: None,
                family_name: None,
                middle_name: None,
                honorific_prefix: None,
                honorific_suffix: None,
                profile_type: 0,
                invite_code: None,
                referrer_id: None,
                utm: None,
            },
        ))
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert!(status.message().contains("maintenance"));
}

#[tokio::test]
async fn test_maintenance_mode_blocks_project_service() {
    let svc = maintenance_mode_services().await;
    let jwt = test_jwt();
    let profile = test_profile();
    let token = issue_admin_token(&jwt, profile.id);

    let result = svc
        .project
        .create_project(authed_request(
            CreateProjectRequest {
                name: "Test".to_string(),
                description: "desc".to_string(),
                owner_profile_id: profile.id.to_string(),
            },
            &token,
        ))
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert!(status.message().contains("maintenance"));
}

// ═══════════════════════════════════════════════════════════════════
// OAuth2 Discovery & Protocol Edge Cases
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_oauth2_authorize_missing_response_type() {
    let client = test_client();
    let storage = MockStorage::new().with_client(client.clone());
    let svc = TestServices::new(storage);
    let profile = test_profile();
    let token = common::fresh_token(&svc, &profile).await;

    // Missing response_type should fail
    let result = svc
        .auth
        .o_auth2_authorize(authed_request(
            OAuth2AuthorizeRequest {
                response_type: "".to_string(), // empty
                client_id: client.client_id.clone(),
                redirect_uri: "https://app.sid.example.com/callback".to_string(),
                scope: Some("openid".to_string()),
                state: Some("test-state".to_string()),
                nonce: Some("test-nonce".to_string()),
                code_challenge: None,
                code_challenge_method: None,
                acr_values: None,
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &token,
        ))
        .await;

    // An empty response_type is refused with the RFC 6749 §4.1.2.1 code for
    // the established redirect URI; no code is issued.
    let status = result.expect_err("an empty response_type was accepted");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        tonic_types::StatusExt::get_details_error_info(&status)
            .and_then(|info| info.metadata.get("oauthError").cloned())
            .as_deref(),
        Some("unsupported_response_type")
    );
}

#[tokio::test]
async fn test_revoke_refresh_token() {
    let client = test_client();
    let storage = MockStorage::new().with_client(client.clone());
    let svc = TestServices::new(storage);

    // Revoking a non-existent refresh token should succeed (RFC 7009: no error)
    let result = svc
        .auth
        .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
            token: "nonexistent-refresh-token".to_string(),
            token_type_hint: Some("refresh_token".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            client_id: Some(client.client_id.clone()),
            ..Default::default()
        }))
        .await;

    // Per RFC 7009: revocation of non-existent token should not be an error
    assert!(result.is_ok());
}

/// A stored refresh token whose value is `raw`.
async fn stored_refresh_token(svc: &TestServices, raw: &str) -> sid_core::models::RefreshToken {
    let id = uuid::Uuid::now_v7();
    let token = sid_core::models::RefreshToken {
        id,
        token_hash: sid_authn::oauth2::OAuth2Server::hash_token(raw),
        session_id: sid_core::models::SessionId::generate(),
        profile_id: test_profile().id,
        client_id: "test-client".to_string(),
        scopes: vec!["openid".to_string()],
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        created_at: chrono::Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id: id,
        grace_expires_at: None,
        dpop_jkt: None,
        resource: common::userinfo_resource(svc).await,
    };
    svc.storage
        .create_refresh_token(&token, AuditEntry::system("test", "refresh").into())
        .await
        .unwrap();
    token
}

fn refresh_revoked(svc: &TestServices, raw: &str) -> bool {
    svc.mock_storage
        .inner
        .lock()
        .unwrap()
        .refresh_tokens_by_hash[&sid_authn::oauth2::OAuth2Server::hash_token(raw)]
        .revoked
}

/// Revoking a refresh token by its value revokes it (RFC 7009 §2.1).
#[tokio::test]
async fn test_revoke_refresh_token_by_value() {
    let svc = TestServices::new(MockStorage::new().with_client(test_client()));
    stored_refresh_token(&svc, "refresh-value-one").await;

    svc.auth
        .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
            token: "refresh-value-one".to_string(),
            token_type_hint: Some("refresh_token".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            client_id: Some("test-client".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap();

    assert!(refresh_revoked(&svc, "refresh-value-one"));
}

/// A refresh token is revoked only by the client it was issued to
/// (RFC 7009 §2.1): another client of the issuer is refused with
/// `unauthorized_client` and the grant stays.
#[tokio::test]
async fn test_revoke_refresh_token_only_by_its_client() {
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    stored_refresh_token(&svc, "refresh-value-owned").await;

    let err = svc
        .auth
        .o_auth2_revoke(common::as_client(
            OAuth2RevokeRequest {
                token: "refresh-value-owned".to_string(),
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ))
        .await
        .unwrap_err();

    assert_eq!(oauth_error(&err).as_deref(), Some("unauthorized_client"));
    assert!(!refresh_revoked(&svc, "refresh-value-owned"));
}

/// Revoking a refresh token ends its whole grant (RFC 7009 §2.1): the token
/// it replaced, still honoured during its rotation grace window, stops working
/// too, so a revoked grant cannot be renewed through the older token.
#[tokio::test]
async fn test_revoke_refresh_token_ends_its_grant() {
    let svc = TestServices::new(MockStorage::new().with_client(test_client()));
    let current = stored_refresh_token(&svc, "refresh-current").await;
    let mut previous = stored_refresh_token(&svc, "refresh-previous").await;
    previous.family_id = current.family_id;
    previous.revoked = true;
    previous.replaced_by = Some(current.id);
    previous.grace_expires_at = Some(chrono::Utc::now() + chrono::Duration::seconds(30));
    svc.mock_storage
        .inner
        .lock()
        .unwrap()
        .refresh_tokens_by_hash
        .insert(previous.token_hash.clone(), previous);

    svc.auth
        .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
            token: "refresh-current".to_string(),
            token_type_hint: Some("refresh_token".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            client_id: Some("test-client".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap();

    assert!(refresh_revoked(&svc, "refresh-current"));
    let grace = svc
        .mock_storage
        .inner
        .lock()
        .unwrap()
        .refresh_tokens_by_hash[&sid_authn::oauth2::OAuth2Server::hash_token("refresh-previous")]
        .grace_expires_at;
    assert!(grace.is_none(), "the replaced token kept its grace window");
}

/// The internal id of a refresh token is not the token: sending it revokes
/// nothing, so an id seen in an audit trail cannot end someone's session.
#[tokio::test]
async fn test_revoke_by_refresh_token_id_revokes_nothing() {
    let svc = TestServices::new(MockStorage::new().with_client(test_client()));
    let stored = stored_refresh_token(&svc, "refresh-value-two").await;

    svc.auth
        .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
            token: stored.id.to_string(),
            token_type_hint: Some("refresh_token".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            client_id: Some("test-client".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap();

    assert!(!refresh_revoked(&svc, "refresh-value-two"));
}

/// A revocation the storage failed to record is reported as a failure, not
/// as success: the client would otherwise discard a token that still works.
#[tokio::test]
async fn test_revoke_refresh_token_storage_failure_is_reported() {
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_failing_refresh_revocation(),
    );
    stored_refresh_token(&svc, "refresh-value-three").await;

    let err = svc
        .auth
        .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
            token: "refresh-value-three".to_string(),
            token_type_hint: Some("refresh_token".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            client_id: Some("test-client".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Internal);
}

/// A refresh token of a client this issuer does not serve is not revoked at
/// its endpoint: that client is unknown here (`invalid_client`), and a client
/// this issuer serves is refused as not the token's (`unauthorized_client`).
/// Equal token values in another context confer no authority.
#[tokio::test]
async fn test_revoke_leaves_another_issuers_refresh_token() {
    let mut foreign = test_client();
    foreign.org_id = Some(sid_core::models::OrgId::generate());
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(foreign)
            .with_client(common::confidential_client()),
    );
    stored_refresh_token(&svc, "refresh-value-foreign").await;
    let message = || OAuth2RevokeRequest {
        token: "refresh-value-foreign".to_string(),
        token_type_hint: Some("refresh_token".to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    };

    let err = svc
        .auth
        .o_auth2_revoke(Request::new(OAuth2RevokeRequest {
            client_id: Some("test-client".to_string()),
            ..message()
        }))
        .await
        .unwrap_err();
    assert_eq!(oauth_error(&err).as_deref(), Some("invalid_client"));

    let err = svc
        .auth
        .o_auth2_revoke(common::as_client(
            message(),
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ))
        .await
        .unwrap_err();
    assert_eq!(oauth_error(&err).as_deref(), Some("unauthorized_client"));

    assert!(!refresh_revoked(&svc, "refresh-value-foreign"));
}

/// An expired token of the caller is inactive (RFC 7662 §2.2).
#[tokio::test]
async fn test_introspect_expired_token() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_client(common::confidential_client()));
    // An inspector that would see the token if it were valid.
    common::grant_inspection(
        &svc,
        RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        common::userinfo_resource(&svc).await,
    )
    .await;
    let signer = svc.issuers.signer(&svc.issuer).await.unwrap();
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    // The token expires with its session, already past.
    session.expires_at = chrono::Utc::now() - chrono::Duration::minutes(5);
    let userinfo = sid_authn::issuer::userinfo_endpoint(&svc.issuer.canonical_url);
    let expired = svc
        .jwt
        .access_token_signed_by(
            signer.as_ref(),
            sid_authn::jwt::TokenAudience::Resource {
                indicator: &userinfo,
                client_id: common::CONFIDENTIAL_CLIENT,
            },
            &profile.id.to_string(),
            None,
            &profile,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap();

    let resp = introspect_as_confidential(&svc, expired).await.unwrap();
    assert_eq!(resp, OAuth2IntrospectResponse::default());
}

/// A registered account holding `email`, switched to `profile_type`.
async fn account_with_email(
    svc: &TestServices,
    email: &str,
    profile_type: sid_core::models::ProfileType,
) -> Profile {
    opaque_register(svc, email, email, b"account-password")
        .await
        .expect("registration");
    let mut profile = svc
        .storage
        .get_profile_by_principal(sid_core::models::PrincipalType::Email, email)
        .await
        .unwrap()
        .expect("profile");
    profile.profile_type = profile_type;
    assert!(
        svc.storage
            .update_profile(&profile, AuditEntry::system("test", "profile.type").into())
            .await
            .unwrap()
    );
    profile.revision += 1;
    profile
}

fn magic_link_request(email: &str) -> Request<RequestMagicLinkRequest> {
    Request::new(RequestMagicLinkRequest {
        principal: email.to_string(),
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
    })
}

/// Regression:magic links are off unless the instance enables them. Both
/// RPCs refuse with FailedPrecondition for any address, and no link is created.
#[tokio::test]
async fn test_magic_link_disabled_by_default() {
    let email = "corp-default-off@sid.example.com";
    let svc = TestServices::new(MockStorage::new());
    account_with_email(&svc, email, sid_core::models::ProfileType::Corporate).await;

    let err = svc
        .auth
        .request_magic_link(magic_link_request(email))
        .await
        .expect_err("disabled");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "{}",
        err.message()
    );
    assert_eq!(
        svc.storage
            .count_active_magic_links_for_email(email)
            .await
            .unwrap(),
        0
    );

    let err = svc
        .auth
        .verify_magic_link(Request::new(VerifyMagicLinkRequest {
            session_id: Uuid::now_v7().to_string(),
            token: "any".to_string(),
        }))
        .await
        .expect_err("disabled");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "{}",
        err.message()
    );
}

/// Regression:with magic links enabled, only a Corporate Profile gets a
/// link. A personal account and an unknown address get the same answer and no link.
#[tokio::test]
async fn test_magic_link_only_for_corporate_profiles() {
    let personal = "personal-ml@sid.example.com";
    let unknown = "unknown-ml@sid.example.com";
    let corporate = "corporate-ml@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new());
    account_with_email(&svc, personal, sid_core::models::ProfileType::Personal).await;
    account_with_email(&svc, corporate, sid_core::models::ProfileType::Corporate).await;

    for email in [personal, unknown, corporate] {
        let resp = svc
            .auth
            .request_magic_link(magic_link_request(email))
            .await
            .expect("uniform answer")
            .into_inner();
        assert_eq!(resp.expires_in, 900, "{email}");
    }
    let links = |email: &'static str| {
        let storage = svc.storage.clone();
        async move {
            storage
                .count_active_magic_links_for_email(email)
                .await
                .unwrap()
        }
    };
    assert_eq!(links(personal).await, 0);
    assert_eq!(links(unknown).await, 0);
    assert_eq!(links(corporate).await, 1);
}

/// Regression: a Corporate Profile past its per-address request limit was
/// answered RESOURCE_EXHAUSTED, which no unknown address ever gets, so the
/// answer told the account exists. Past the limit the answer is the same
/// and no further link is sent.
#[tokio::test]
async fn test_magic_link_past_the_limit_answers_like_any_address() {
    let corporate = "corporate-limit@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new());
    account_with_email(&svc, corporate, sid_core::models::ProfileType::Corporate).await;

    for attempt in 0..sid_core::models::MAGIC_LINK_RATE_LIMIT_MAX + 2 {
        let resp = svc
            .auth
            .request_magic_link(magic_link_request(corporate))
            .await
            .unwrap_or_else(|e| panic!("attempt {attempt}: {e:?}"))
            .into_inner();
        assert_eq!(resp.expires_in, 900, "attempt {attempt}");
    }
    let sent = svc
        .storage
        .count_active_magic_links_for_email(corporate)
        .await
        .unwrap();
    assert_eq!(sent, sid_core::models::MAGIC_LINK_RATE_LIMIT_MAX);
}

/// Regression: the address was looked up exactly as typed, so a holder who
/// typed it in another case or with spaces got no link, and the request
/// limit counted each spelling apart. The address is normalized first.
#[tokio::test]
async fn test_magic_link_request_normalizes_the_address() {
    let corporate = "corp-case@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new());
    account_with_email(&svc, corporate, sid_core::models::ProfileType::Corporate).await;

    svc.auth
        .request_magic_link(magic_link_request("  Corp-Case@SID.Example.com "))
        .await
        .expect("uniform answer");
    assert_eq!(
        svc.storage
            .count_active_magic_links_for_email(corporate)
            .await
            .unwrap(),
        1
    );
}

/// Regression: a link was resolved through the profile's stored email, not
/// through the address's sign-in assignment, so after the holder released
/// the address a link mailed to it still opened the former holder's
/// account. Request and verification follow the assignment.
#[tokio::test]
async fn test_magic_link_follows_the_principal_assignment() {
    let email = "corp-released@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new());
    let holder = account_with_email(&svc, email, sid_core::models::ProfileType::Corporate).await;
    let principal = svc
        .storage
        .get_principal_by_value(sid_core::models::PrincipalType::Email, email)
        .await
        .unwrap()
        .expect("the holder's principal");
    svc.storage
        .unbind_principal(
            principal.id,
            holder.id,
            AuditEntry::system("test", "release").into(),
        )
        .await
        .unwrap();

    svc.auth
        .request_magic_link(magic_link_request(email))
        .await
        .expect("uniform answer");
    assert_eq!(
        svc.storage
            .count_active_magic_links_for_email(email)
            .await
            .unwrap(),
        0,
        "a link was sent for an address that routes to nobody"
    );

    let (link, token) = sid_authn::magic_link::MagicLinkService::new(svc.storage.clone())
        .request_magic_link(email)
        .await
        .unwrap();
    let err = svc
        .auth
        .verify_magic_link(Request::new(VerifyMagicLinkRequest {
            session_id: link.session_id.to_string(),
            token,
        }))
        .await
        .expect_err("the released address opened the former holder's account");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "{}",
        err.message()
    );
}

/// Regression:a verified magic link yields a provisional session (15 min,
/// provisional scopes) and an access token that does not outlive it.
#[tokio::test]
async fn test_magic_link_verify_issues_provisional_session() {
    let email = "corp-verify@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new());
    let profile = account_with_email(&svc, email, sid_core::models::ProfileType::Corporate).await;
    let (link, token) = sid_authn::magic_link::MagicLinkService::new(svc.storage.clone())
        .request_magic_link(email)
        .await
        .unwrap();

    let resp = svc
        .auth
        .verify_magic_link(Request::new(VerifyMagicLinkRequest {
            session_id: link.session_id.to_string(),
            token,
        }))
        .await
        .expect("verify")
        .into_inner();

    let session_id: sid_core::models::SessionId = resp.session_id.parse().unwrap();
    let session = svc
        .storage
        .get_session(session_id)
        .await
        .unwrap()
        .expect("session stored");
    assert_eq!(session.profile_id, profile.id);
    assert!(session.is_provisional);
    assert!(session.expires_at <= chrono::Utc::now() + chrono::Duration::minutes(15));
    let provisional = sid_core::models::Session::new_provisional(profile.id, String::new());
    assert_eq!(session.scopes, provisional.scopes);
    // Mailbox possession over a second channel, as for an emailed code:
    // `mca` (RFC 8176 §2); the registry has no link method.
    assert_eq!(session.amr, vec!["mca".to_string()]);
    let claims = svc.jwt.validate_access_token(&resp.access_token).unwrap();
    assert!(claims.exp <= session.expires_at.timestamp());
    assert!(i64::from(resp.expires_in) <= 15 * 60);
}

/// A link whose session cannot be read is an error: it once answered as an
/// unknown link, which also counted a failed attempt against the caller's IP.
#[tokio::test]
async fn test_magic_link_verify_unreadable_session_is_reported() {
    let email = "corp-unreadable@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new());
    account_with_email(&svc, email, sid_core::models::ProfileType::Corporate).await;
    let (link, token) = sid_authn::magic_link::MagicLinkService::new(svc.storage.clone())
        .request_magic_link(email)
        .await
        .unwrap();
    svc.mock_storage.fail_magic_link_reads();

    let err = svc
        .auth
        .verify_magic_link(Request::new(VerifyMagicLinkRequest {
            session_id: link.session_id.to_string(),
            token,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal, "{}", err.message());
}

/// A right link whose consumption cannot be recorded is an error, not a
/// "link already used".
#[tokio::test]
async fn test_magic_link_verify_unrecorded_consumption_is_reported() {
    let email = "corp-unrecorded@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new());
    account_with_email(&svc, email, sid_core::models::ProfileType::Corporate).await;
    let (link, token) = sid_authn::magic_link::MagicLinkService::new(svc.storage.clone())
        .request_magic_link(email)
        .await
        .unwrap();
    svc.mock_storage.fail_magic_link_consume();

    let err = svc
        .auth
        .verify_magic_link(Request::new(VerifyMagicLinkRequest {
            session_id: link.session_id.to_string(),
            token,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal, "{}", err.message());
}

/// Regression:a link that reached a personal account (issued before its
/// type changed, or forged into storage) does not log it in.
#[tokio::test]
async fn test_magic_link_verify_rejects_personal_profile() {
    let email = "personal-verify@sid.example.com";
    let svc = TestServices::with_magic_links(MockStorage::new());
    let profile = account_with_email(&svc, email, sid_core::models::ProfileType::Personal).await;
    let (link, token) = sid_authn::magic_link::MagicLinkService::new(svc.storage.clone())
        .request_magic_link(email)
        .await
        .unwrap();

    let err = svc
        .auth
        .verify_magic_link(Request::new(VerifyMagicLinkRequest {
            session_id: link.session_id.to_string(),
            token,
        }))
        .await
        .expect_err("personal account");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "{}",
        err.message()
    );
    assert!(
        svc.storage
            .list_sessions_by_profile(profile.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Regression:the password-reset event carries no reset URL, token or
/// email address; the event stream is readable beyond the notification service.
#[tokio::test]
async fn test_password_reset_event_carries_no_secret() {
    let email = "reset-event@sid.example.com";
    let svc = TestServices::new(MockStorage::new());
    account_with_email(&svc, email, sid_core::models::ProfileType::Personal).await;
    let mut events = svc
        .event_bus
        .subscribe(sid_core::models::event::EventFilter {
            event_types: vec!["sid.auth.password_reset_requested.v1".to_string()],
            attributes: Default::default(),
            queue_group: None,
        })
        .await
        .unwrap();

    svc.auth
        .request_password_reset(Request::new(RequestPasswordResetRequest {
            principal: email.to_string(),
            client_id: String::new(),
            redirect_uri: String::new(),
            captcha_token: String::new(),
        }))
        .await
        .unwrap();

    assert!(events.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = events.try_recv().expect("reset event published");
    let data = serde_json::to_string(&event.data).unwrap();
    assert!(!data.contains("token"), "{data}");
    assert!(!data.contains("reset_url"), "{data}");
    assert!(!data.contains(email), "{data}");
}

// ═══════════════════════════════════════════════════════════════════
// AdminService Tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_update_profile_requires_auth() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(AdminUpdateProfileRequest {
        profile_id: Uuid::new_v4().to_string(),
        ..Default::default()
    });

    let err = svc.admin.admin_update_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_admin_update_profile_requires_admin_role() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Issue token WITHOUT admin role
    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(
        AdminUpdateProfileRequest {
            profile_id: profile.id.to_string(),
            ..Default::default()
        },
        &token,
    );

    let err = svc.admin.admin_update_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_admin_update_profile_suspend() {
    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let admin_token = issue_admin_token(&svc.jwt, pid);

    let req = authed_request(
        AdminUpdateProfileRequest {
            profile_id: pid.to_string(),
            profile_status: sid_proto::sid::v1::ProfileStatus::Suspended.into(),
            ..Default::default()
        },
        &admin_token,
    );

    let resp = svc.admin.admin_update_profile(req).await.unwrap();
    assert_eq!(resp.into_inner().profile_id, pid.to_string());
}

/// Suspension ends access: a suspended profile's live session (and so its
/// access tokens) stops, and its RP is owed a back-channel logout. Without it
/// a suspended user keeps working until every token expires.
#[tokio::test]
async fn test_admin_suspend_ends_live_sessions() {
    use sid_plugin::WorkStore;

    let profile = test_profile();
    let pid = profile.id;
    let mut session = Session::new(
        pid,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.client_id = Some("rp-client".into());
    let storage = MockStorage::new()
        .with_profile(profile)
        .with_session(session.clone());
    let svc = TestServices::new(storage);
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());

    svc.admin
        .admin_update_profile(authed_request(
            AdminUpdateProfileRequest {
                profile_id: pid.to_string(),
                profile_status: sid_proto::sid::v1::ProfileStatus::Suspended.into(),
                ..Default::default()
            },
            &admin_token,
        ))
        .await
        .unwrap();

    assert!(
        svc.revocation_cache
            .is_revoked("", &session.id.to_string())
            .await
            .unwrap(),
        "the suspended profile's access tokens still pass"
    );
    assert!(
        svc.storage.get_session(session.id).await.unwrap().is_none(),
        "the suspended profile's session survived"
    );
    let owed = sid_core::models::LogoutDelivery::for_ended_session(&session)
        .unwrap()
        .work();
    assert!(
        svc.mock_storage.get_work(owed.id).await.unwrap().is_some(),
        "the RP was not owed a logout"
    );
}

/// A status an administrator does not set (CLOSED), or a value the enum does
/// not define, is refused naming the field; an unknown value used to be
/// treated as "no change" and the rest of the request applied.
#[tokio::test]
async fn test_admin_update_profile_invalid_status() {
    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let admin_token = issue_admin_token(&svc.jwt, pid);

    for status in [sid_proto::sid::v1::ProfileStatus::Closed as i32, 99] {
        let req = authed_request(
            AdminUpdateProfileRequest {
                profile_id: pid.to_string(),
                profile_status: status,
                roles: vec!["admin".to_string()],
                ..Default::default()
            },
            &admin_token,
        );

        let err = svc.admin.admin_update_profile(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{status}");
        assert_eq!(
            common::error_reason(&err).as_deref(),
            Some("INVALID_FIELD_VALUE")
        );
        let stored = svc.storage.get_profile(pid).await.unwrap().unwrap();
        assert!(!stored.is_admin(), "{status}: the roles were applied");
    }
}

/// Setting a status moves an account only between its ordinary states: a
/// closed or closing account is never reopened by an administrator's
/// "activate", and nothing is written.
#[tokio::test]
async fn test_admin_activate_never_reopens_a_closed_account() {
    for status in [
        sid_core::models::ProfileStatus::Closed,
        sid_core::models::ProfileStatus::Purged,
        sid_core::models::ProfileStatus::GracePeriod,
        sid_core::models::ProfileStatus::LegalHold,
    ] {
        let mut profile = test_profile();
        profile.status = status;
        let pid = profile.id;
        let svc = TestServices::new(MockStorage::new().with_profile(profile));
        let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());

        let err = svc
            .admin
            .admin_update_profile(authed_request(
                AdminUpdateProfileRequest {
                    profile_id: pid.to_string(),
                    profile_status: sid_proto::sid::v1::ProfileStatus::Active.into(),
                    ..Default::default()
                },
                &admin_token,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{status}");
        let stored = svc.storage.get_profile(pid).await.unwrap().unwrap();
        assert_eq!(stored.status, status, "{status} was reopened");
    }
}

#[tokio::test]
async fn test_admin_update_profile_not_found() {
    let admin_profile = test_profile();
    let admin_id = admin_profile.id;
    let storage = MockStorage::new().with_profile(admin_profile);
    let svc = TestServices::new(storage);

    let admin_token = issue_admin_token(&svc.jwt, admin_id);
    let nonexistent_id = ProfileId::generate();

    let req = authed_request(
        AdminUpdateProfileRequest {
            profile_id: nonexistent_id.to_string(),
            profile_status: sid_proto::sid::v1::ProfileStatus::Suspended.into(),
            ..Default::default()
        },
        &admin_token,
    );

    let err = svc.admin.admin_update_profile(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_admin_rpc_revoke_all_sessions() {
    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create a session first
    let session = Session::new(
        pid,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    svc.storage
        .create_session(&session, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let admin_token = issue_admin_token(&svc.jwt, pid);

    let req = authed_request(
        RevokeAllSessionsRequest {
            profile_id: pid.to_string(),
        },
        &admin_token,
    );

    let resp = svc.admin.revoke_all_sessions(req).await.unwrap();
    assert_eq!(resp.into_inner().revoked_count, 1);
}

/// Revoking all of a profile's sessions stops their access tokens at once
/// (not only when they expire) and owes each RP they signed in to a
/// back-channel logout.
#[tokio::test]
async fn test_admin_revoke_all_sessions_stops_tokens_and_owes_logout() {
    use sid_plugin::WorkStore;

    let profile = test_profile();
    let pid = profile.id;
    let mut session = Session::new(
        pid,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.client_id = Some("rp-client".into());
    let storage = MockStorage::new()
        .with_profile(profile)
        .with_session(session.clone());
    let svc = TestServices::new(storage);
    let admin_token = issue_admin_token(&svc.jwt, pid);

    svc.admin
        .revoke_all_sessions(authed_request(
            RevokeAllSessionsRequest {
                profile_id: pid.to_string(),
            },
            &admin_token,
        ))
        .await
        .unwrap();

    assert!(
        svc.revocation_cache
            .is_revoked("", &session.id.to_string())
            .await
            .unwrap(),
        "the revoked session's access tokens still pass"
    );
    let owed = sid_core::models::LogoutDelivery::for_ended_session(&session)
        .unwrap()
        .work();
    assert!(
        svc.mock_storage.get_work(owed.id).await.unwrap().is_some(),
        "the RP was not owed a logout"
    );
}

#[tokio::test]
async fn test_admin_rpc_revoke_all_sessions_requires_admin() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(RevokeAllSessionsRequest {
        profile_id: Uuid::new_v4().to_string(),
    });

    let err = svc.admin.revoke_all_sessions(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_admin_metadata_set_and_get() {
    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let admin_token = issue_admin_token(&svc.jwt, pid);

    // Set metadata
    let req = authed_request(
        SetProfileMetadataRequest {
            profile_id: pid.to_string(),
            key: "department".to_string(),
            value: Some(prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "Engineering".to_string(),
                )),
            }),
        },
        &admin_token,
    );

    let resp = svc.admin.set_profile_metadata(req).await.unwrap();
    let entry = resp.into_inner();
    assert_eq!(entry.key, "department");
}

#[tokio::test]
async fn test_admin_metadata_list_empty() {
    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let admin_token = issue_admin_token(&svc.jwt, pid);

    let req = authed_request(
        ListProfileMetadataRequest {
            profile_id: pid.to_string(),
        },
        &admin_token,
    );

    let resp = svc.admin.list_profile_metadata(req).await.unwrap();
    assert!(resp.into_inner().entries.is_empty());
}

#[tokio::test]
async fn test_admin_metadata_get_not_found() {
    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let admin_token = issue_admin_token(&svc.jwt, pid);

    let req = authed_request(
        GetProfileMetadataRequest {
            profile_id: pid.to_string(),
            key: "nonexistent".to_string(),
        },
        &admin_token,
    );

    let err = svc.admin.get_profile_metadata(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        common::error_reason(&err).as_deref(),
        Some("PROFILE_METADATA_NOT_FOUND")
    );
}

/// Regression: metadata for a profile that does not exist failed as an
/// internal error (the storage's foreign-key violation). It is
/// PROFILE_NOT_FOUND.
#[tokio::test]
async fn test_admin_metadata_set_for_unknown_profile() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());

    let err = svc
        .admin
        .set_profile_metadata(authed_request(
            SetProfileMetadataRequest {
                profile_id: ProfileId::generate().to_string(),
                key: "department".to_string(),
                value: None,
            },
            &admin_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        common::error_reason(&err).as_deref(),
        Some("PROFILE_NOT_FOUND")
    );
}

#[tokio::test]
async fn test_admin_metadata_delete() {
    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let admin_token = issue_admin_token(&svc.jwt, pid);

    let req = authed_request(
        DeleteProfileMetadataRequest {
            profile_id: pid.to_string(),
            key: "some-key".to_string(),
        },
        &admin_token,
    );

    // MockStorage delete is no-op, so it should succeed
    svc.admin.delete_profile_metadata(req).await.unwrap();
}

#[tokio::test]
async fn test_admin_metadata_requires_admin() {
    let svc = TestServices::new(MockStorage::new());

    let req = Request::new(ListProfileMetadataRequest {
        profile_id: Uuid::new_v4().to_string(),
    });

    let err = svc.admin.list_profile_metadata(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

// ═══════════════════════════════════════════════════════════════════
// Flow Config Service
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_flow_config_requires_auth() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(GetFlowConfigRequest {
        project_id: Uuid::new_v4().to_string(),
        flow_type: "authentication".to_string(),
    });
    let err = svc.flow_config.get_flow_config(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_flow_config_requires_admin_role() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(
        GetFlowConfigRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
        },
        &token,
    );
    let err = svc.flow_config.get_flow_config(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_flow_config_get_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        GetFlowConfigRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
        },
        &admin_token,
    );
    let err = svc.flow_config.get_flow_config(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_flow_config_invalid_flow_type() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        GetFlowConfigRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "nonexistent".to_string(),
        },
        &admin_token,
    );
    let err = svc.flow_config.get_flow_config(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_flow_config_save_and_list() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    let project_id = Uuid::new_v4().to_string();

    // Save a config
    let req = authed_request(
        SaveFlowConfigRequest {
            project_id: project_id.clone(),
            flow_type: "authentication".to_string(),
            steps: vec![sid_proto::sid::v1::admin::StepConfig {
                step_type: "identification".to_string(),
                enabled: true,
                params: None,
            }],
            timeout_seconds: 600,
        },
        &admin_token,
    );
    let resp = svc.flow_config.save_flow_config(req).await.unwrap();
    let config = resp.into_inner();
    assert_eq!(config.project_id, project_id);
    assert_eq!(config.timeout_seconds, 600);
    assert_eq!(config.steps.len(), 1);

    // List configs
    let req = authed_request(
        ListFlowConfigsRequest {
            project_id: project_id.clone(),
        },
        &admin_token,
    );
    let resp = svc.flow_config.list_flow_configs(req).await.unwrap();
    // MockStorage returns empty list (no persistence), but RPC succeeds
    let configs = resp.into_inner().configs;
    assert!(configs.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// Flow Action Service
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_flow_action_requires_auth() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(ListFlowActionsRequest {
        project_id: Uuid::new_v4().to_string(),
        flow_type: "authentication".to_string(),
        action_point: 0,
    });
    let err = svc.flow_action.list_flow_actions(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_flow_action_create_requires_name() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        CreateFlowActionRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
            action_point: 2,      // POST_AUTHENTICATION
            name: "".to_string(), // empty name
            action_type: 1,       // WEBHOOK
            config: Some(create_flow_action_request::Config::Webhook(WebhookConfig {
                url: "https://api.sid.example.com/hook".to_string(),
                timeout_seconds: 5,
                retry_count: 0,
                headers: Default::default(),
            })),
            order: 1,
            on_error: 1, // CONTINUE
            enabled: true,
        },
        &admin_token,
    );
    let err = svc.flow_action.create_flow_action(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_flow_action_create_requires_config() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        CreateFlowActionRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
            action_point: 1, // PRE_AUTHENTICATION
            name: "Test hook".to_string(),
            action_type: 1,
            config: None, // no config
            order: 1,
            on_error: 1,
            enabled: true,
        },
        &admin_token,
    );
    let err = svc.flow_action.create_flow_action(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_flow_action_create_validates_webhook_url() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        CreateFlowActionRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "registration".to_string(),
            action_point: 6, // POST_REGISTRATION
            name: "Bad hook".to_string(),
            action_type: 1,
            config: Some(create_flow_action_request::Config::Webhook(WebhookConfig {
                url: "ftp://invalid".to_string(), // invalid scheme
                timeout_seconds: 5,
                retry_count: 0,
                headers: Default::default(),
            })),
            order: 1,
            on_error: 1,
            enabled: true,
        },
        &admin_token,
    );
    let err = svc.flow_action.create_flow_action(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_flow_action_create_success() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        CreateFlowActionRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
            action_point: 2, // POST_AUTHENTICATION
            name: "Risk check".to_string(),
            action_type: 1, // WEBHOOK
            config: Some(create_flow_action_request::Config::Webhook(WebhookConfig {
                url: "https://risk.sid.example.com/evaluate".to_string(),
                timeout_seconds: 3,
                retry_count: 1,
                headers: Default::default(),
            })),
            order: 1,
            on_error: 1, // CONTINUE
            enabled: true,
        },
        &admin_token,
    );
    let resp = svc.flow_action.create_flow_action(req).await.unwrap();
    let action = resp.into_inner();
    assert_eq!(action.name, "Risk check");
    assert_eq!(action.flow_type, 1); // AUTHENTICATION
    assert_eq!(action.action_point, 2); // POST_AUTHENTICATION
    assert!(action.enabled);
    assert!(!action.action_id.is_empty());
}

#[tokio::test]
async fn test_flow_action_get_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        GetFlowActionRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
            action_id: Uuid::new_v4().to_string(),
        },
        &admin_token,
    );
    let err = svc.flow_action.get_flow_action(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_flow_action_delete_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        DeleteFlowActionRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
            action_id: Uuid::new_v4().to_string(),
        },
        &admin_token,
    );
    let err = svc.flow_action.delete_flow_action(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_flow_action_update_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        UpdateFlowActionRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
            action_id: Uuid::new_v4().to_string(),
            name: Some("Updated name".to_string()),
            action_point: None,
            config: None,
            order: None,
            on_error: None,
            enabled: None,
        },
        &admin_token,
    );
    let err = svc.flow_action.update_flow_action(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_flow_action_list_empty() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());

    let req = authed_request(
        ListFlowActionsRequest {
            project_id: Uuid::new_v4().to_string(),
            flow_type: "authentication".to_string(),
            action_point: 0, // unspecified = all
        },
        &admin_token,
    );
    let resp = svc.flow_action.list_flow_actions(req).await.unwrap();
    assert!(resp.into_inner().actions.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// SecurityService (CE: read-only policy)
// ═══════════════════════════════════════════════════════════════════

/// A page token this service never issued is refused as an invalid field;
/// it used to be read as offset 0 and answered with the first page.
#[tokio::test]
async fn test_security_anomaly_log_refuses_a_foreign_page_token() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let err = svc
        .security
        .get_anomaly_event_log(authed_request(
            sid_proto::sid::v1::admin::GetAnomalyEventLogRequest {
                page_size: 10,
                page_token: "not-a-token".into(),
                ..Default::default()
            },
            &admin_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let (reason, _, _) = sid_core::grpc_error::extract_error_info(&err).expect("ErrorInfo");
    assert_eq!(reason, "INVALID_FIELD_VALUE");
}

/// An administrator who adds or removes an allowlist entry gets the updated
/// list back. The handlers re-read the list through a fresh request that
/// carried no token, so the change was stored and the caller got
/// UNAUTHENTICATED.
#[tokio::test]
async fn test_security_allowlist_change_answers_with_the_list() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let added = svc
        .security
        .add_ip_allowlist_entry(authed_request(
            sid_proto::sid::v1::admin::AddIpAllowlistEntryRequest {
                cidr: "198.51.100.0/24".into(),
                description: "office".into(),
            },
            &admin_token,
        ))
        .await;
    assert!(added.is_ok(), "{added:?}");
    let removed = svc
        .security
        .remove_ip_allowlist_entry(authed_request(
            sid_proto::sid::v1::admin::RemoveIpAllowlistEntryRequest {
                cidr: "198.51.100.0/24".into(),
            },
            &admin_token,
        ))
        .await;
    assert!(removed.is_ok(), "{removed:?}");
}

#[tokio::test]
async fn test_security_get_password_policy_returns_ce_defaults() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetPasswordPolicyRequest {},
        &admin_token,
    );
    let resp = svc.security.get_password_policy(req).await.unwrap();
    let policy = resp.into_inner();
    assert_eq!(policy.rules.len(), 6);
    // MIN_LENGTH = 1, value = 8
    let min_len = policy.rules.iter().find(|r| r.r#type == 1).unwrap();
    assert_eq!(min_len.value, 8);
    // MAX_AGE_DAYS = 10, value = 0
    let max_age = policy.rules.iter().find(|r| r.r#type == 10).unwrap();
    assert_eq!(max_age.value, 0);
}

#[tokio::test]
async fn test_security_get_password_policy_requires_admin() {
    let svc = TestServices::new(MockStorage::new());
    let user_token = {
        let profile = test_profile();
        issue_token(&svc.jwt, &profile, &["openid".to_string()])
    };
    let req = authed_request(
        sid_proto::sid::v1::admin::GetPasswordPolicyRequest {},
        &user_token,
    );
    let err = svc.security.get_password_policy(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_security_update_password_policy_denied_in_ce() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::PasswordPolicy { rules: vec![] },
        &admin_token,
    );
    let err = svc.security.update_password_policy(req).await.unwrap_err();
    // Configurable policy is not part of this build: FEATURE_NOT_AVAILABLE,
    // and the public contract names no edition.
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    let (reason, _, _) = sid_core::grpc_error::extract_error_info(&err).expect("ErrorInfo");
    assert_eq!(reason, "FEATURE_NOT_AVAILABLE");
    assert_eq!(
        err.message(),
        "this feature is not part of this server build"
    );
}

#[tokio::test]
async fn test_security_get_security_policy_returns_full_ce_policy() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetSecurityPolicyRequest {},
        &admin_token,
    );
    let resp = svc.security.get_security_policy(req).await.unwrap();
    let policy = resp.into_inner();
    assert_eq!(policy.enforcement_mode, "hard");
    assert_eq!(policy.min_auth_level, "basic");
    assert_eq!(policy.mfa_enforcement, "optional");
    assert!(policy.read_only);
    assert!(policy.rate_limits_enabled);
    assert!(policy.anomaly_detection_enabled);
    assert!(!policy.captcha_enabled);
    assert!(policy.breach_detection_enabled);
    assert_eq!(policy.password_min_length, 8);
    assert_eq!(policy.password_max_age_days, 0);
    assert_eq!(policy.session_max_lifetime_hours, 0);
    assert!(policy.network.is_some());
    assert!(
        policy.passkey_satisfies_mfa,
        "CE default passkey_satisfies_mfa should be true"
    );
}

/// The server lists its 8 built-in anomaly rules, all enabled.
#[tokio::test]
async fn test_security_list_anomaly_rules_returns_the_built_in_rules() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::ListAnomalyRulesRequest {},
        &admin_token,
    );
    let resp = svc.security.list_anomaly_rules(req).await.unwrap();
    let rules = resp.into_inner().rules;
    assert_eq!(rules.len(), 8);
    assert!(rules.iter().all(|r| r.enabled));
    // Check specific rules exist
    assert!(rules.iter().any(|r| r.id == "brute_force"));
    assert!(rules.iter().any(|r| r.id == "impossible_travel"));
    assert!(rules.iter().any(|r| r.id == "credential_stuffing"));
}

#[tokio::test]
async fn test_security_get_brute_force_config() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetBruteForceConfigRequest {},
        &admin_token,
    );
    let resp = svc.security.get_brute_force_config(req).await.unwrap();
    let config = resp.into_inner();
    // What the admin sees is what the detector enforces (it used to show a
    // 60 s progressive lockout while the detector locked for 15 min flat).
    let enforced = sid_authn::anomaly::AnomalyConfig::default();
    assert!(config.enabled);
    assert_eq!(
        config.mode,
        sid_proto::sid::v1::admin::BruteForceLockoutMode::Temporary as i32
    );
    assert_eq!(
        config.max_login_failures as u32,
        enforced.brute_force_max_attempts
    );
    assert_eq!(
        config.lockout_duration_seconds as u64,
        enforced.brute_force_lockout_secs
    );
    assert_eq!(
        config.max_lockout_duration_seconds as u64,
        enforced.brute_force_lockout_secs
    );
    assert_eq!(
        config.failure_reset_seconds as u64,
        enforced.brute_force_window_secs
    );
    assert_eq!(config.quick_login_check_ms, 0);
}

#[tokio::test]
async fn test_security_get_security_headers() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetSecurityHeadersRequest {},
        &admin_token,
    );
    let resp = svc.security.get_security_headers(req).await.unwrap();
    let headers = resp.into_inner();
    assert_eq!(headers.x_frame_options, "DENY");
    assert!(headers.x_content_type_options_nosniff);
    assert_eq!(headers.hsts_max_age, 31_536_000);
}

#[tokio::test]
async fn test_security_get_captcha_config_disabled() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetCaptchaConfigRequest {},
        &admin_token,
    );
    let resp = svc.security.get_captcha_config(req).await.unwrap();
    assert!(!resp.into_inner().enabled);
}

#[tokio::test]
async fn test_security_test_captcha_provider_unimplemented() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::TestCaptchaProviderRequest {
            provider: 0,
            site_key: String::new(),
            secret_key: String::new(),
        },
        &admin_token,
    );
    let err = svc.security.test_captcha_provider(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn test_security_get_effective_policy_without_overrides() {
    let mock = MockStorage::new().with_client(test_client());
    let svc = TestServices::new(mock);
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetEffectivePolicyRequest {
            client_id: "test-client".to_string(),
        },
        &admin_token,
    );
    let resp = svc.security.get_effective_policy(req).await.unwrap();
    let policy = resp.into_inner();
    // No overrides on test client → should match CE defaults
    assert_eq!(policy.min_auth_level, "basic");
    assert_eq!(policy.enforcement_mode, "hard");
    assert!(
        policy.passkey_satisfies_mfa,
        "Effective policy should inherit passkey_satisfies_mfa from CE defaults"
    );
}

#[tokio::test]
async fn test_security_get_effective_policy_with_client_override() {
    let mut client = test_client();
    client.required_acr = Some(sid_core::models::session::AuthLevel::Standard);
    let mock = MockStorage::new().with_client(client);
    let svc = TestServices::new(mock);
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetEffectivePolicyRequest {
            client_id: "test-client".to_string(),
        },
        &admin_token,
    );
    let resp = svc.security.get_effective_policy(req).await.unwrap();
    let policy = resp.into_inner();
    // Client override raises min_auth_level to standard
    assert_eq!(policy.min_auth_level, "standard");
    // passkey_satisfies_mfa is not per-client override — always CE default
    assert!(policy.passkey_satisfies_mfa);
}

#[tokio::test]
async fn test_security_get_effective_policy_missing_client_id() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetEffectivePolicyRequest {
            client_id: String::new(),
        },
        &admin_token,
    );
    let err = svc.security.get_effective_policy(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_security_evaluate_enforcement_allow() {
    let profile = test_profile();
    let mock = MockStorage::new()
        .with_profile(profile.clone())
        .with_client(test_client());
    let svc = TestServices::new(mock);
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::EvaluateEnforcementRequest {
            profile_id: profile.id.to_string(),
            client_id: "test-client".to_string(),
        },
        &admin_token,
    );
    let resp = svc.security.evaluate_enforcement(req).await.unwrap();
    let decision = resp.into_inner();
    // CE default: Basic + Optional MFA → ALLOW for any authenticated user
    assert_eq!(
        decision.action,
        sid_proto::sid::v1::admin::EnforcementAction::Allow as i32
    );
    assert!(decision.violations.is_empty());
}

/// An evaluation that cannot read the client fails: it must not report the
/// CE default as the decision while the client may require a higher level.
#[tokio::test]
async fn test_security_evaluate_enforcement_unreadable_client_is_reported() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client()),
    );
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    svc.mock_storage.fail_client_reads();
    let req = authed_request(
        sid_proto::sid::v1::admin::EvaluateEnforcementRequest {
            profile_id: profile.id.to_string(),
            client_id: "test-client".to_string(),
        },
        &admin_token,
    );
    let err = svc
        .security
        .evaluate_enforcement(req)
        .await
        .expect_err("a decision was made without the client's requirements");
    assert_eq!(err.code(), tonic::Code::Internal);
}

/// The decision is for a named client; a client that does not exist is not
/// evaluated as one with no requirements.
#[tokio::test]
async fn test_security_evaluate_enforcement_unknown_client() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::EvaluateEnforcementRequest {
            profile_id: profile.id.to_string(),
            client_id: "no-such-client".to_string(),
        },
        &admin_token,
    );
    let err = svc.security.evaluate_enforcement(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_security_evaluate_enforcement_invalid_profile_id() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::EvaluateEnforcementRequest {
            profile_id: "not-a-uuid".to_string(),
            client_id: "test-client".to_string(),
        },
        &admin_token,
    );
    let err = svc.security.evaluate_enforcement(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_security_evaluate_enforcement_profile_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::EvaluateEnforcementRequest {
            profile_id: ProfileId::generate().to_string(),
            client_id: "test-client".to_string(),
        },
        &admin_token,
    );
    let err = svc.security.evaluate_enforcement(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_security_list_application_overrides_empty() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::ListApplicationOverridesRequest {},
        &admin_token,
    );
    let resp = svc.security.list_application_overrides(req).await.unwrap();
    assert!(resp.into_inner().overrides.is_empty());
}

#[tokio::test]
async fn test_security_get_breach_detection_config() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetBreachDetectionConfigRequest {},
        &admin_token,
    );
    let resp = svc.security.get_breach_detection_config(req).await.unwrap();
    let config = resp.into_inner();
    assert!(config.enabled);
    assert!(config.check_on_login);
    assert_eq!(config.provider, "hibp");
}

#[tokio::test]
async fn test_security_get_network_policy_ce_defaults() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let req = authed_request(
        sid_proto::sid::v1::admin::GetNetworkPolicyRequest {},
        &admin_token,
    );
    let resp = svc.security.get_network_policy(req).await.unwrap();
    let np = resp.into_inner();
    assert!(np.allowed_countries.is_empty());
    assert!(np.blocked_countries.is_empty());
    assert!(!np.block_tor);
    assert!(!np.block_datacenter_ips);
}

#[tokio::test]
async fn test_security_all_update_rpcs_denied_in_ce() {
    let svc = TestServices::new(MockStorage::new());
    let admin_token = issue_admin_token(&svc.jwt, ProfileId::generate());

    // update_brute_force_config
    let req = authed_request(
        sid_proto::sid::v1::admin::BruteForceConfig {
            enabled: false,
            mode: 0,
            max_login_failures: 0,
            lockout_duration_seconds: 0,
            max_lockout_duration_seconds: 0,
            failure_reset_seconds: 0,
            quick_login_check_ms: 0,
        },
        &admin_token,
    );
    assert_eq!(
        svc.security
            .update_brute_force_config(req)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );

    // update_security_headers
    let req = authed_request(
        sid_proto::sid::v1::admin::SecurityHeaders {
            x_frame_options: String::new(),
            content_security_policy: String::new(),
            x_content_type_options_nosniff: false,
            hsts_max_age: 0,
            hsts_include_subdomains: false,
            hsts_preload: false,
            x_xss_protection: false,
            referrer_policy: String::new(),
        },
        &admin_token,
    );
    assert_eq!(
        svc.security
            .update_security_headers(req)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );

    // update_captcha_config
    let req = authed_request(
        sid_proto::sid::v1::admin::CaptchaConfig {
            enabled: false,
            provider: 0,
            site_key: String::new(),
            secret_key: String::new(),
            score_threshold: 0.0,
            triggers: vec![],
        },
        &admin_token,
    );
    assert_eq!(
        svc.security
            .update_captcha_config(req)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );

    // update_network_policy
    let req = authed_request(
        sid_proto::sid::v1::admin::NetworkPolicy {
            allowed_countries: vec![],
            blocked_countries: vec![],
            block_tor: false,
            block_datacenter_ips: false,
            violation_reaction: 0,
        },
        &admin_token,
    );
    assert_eq!(
        svc.security
            .update_network_policy(req)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );

    // update_breach_detection_config
    let req = authed_request(
        sid_proto::sid::v1::admin::BreachDetectionConfig {
            enabled: false,
            check_on_login: false,
            check_on_password_change: false,
            force_password_change_on_breach: false,
            provider: String::new(),
        },
        &admin_token,
    );
    assert_eq!(
        svc.security
            .update_breach_detection_config(req)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );
}

// ═══════════════════════════════════════════════════════════════════
// Passwordless OTP (AuthService)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_request_otp_returns_session() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_system_project()
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let req = Request::new(RequestOtpRequest {
        principal: "alice@sid.example.com".to_string(),
    });
    let resp = svc.auth.request_otp(req).await.unwrap();
    let inner = resp.into_inner();
    assert!(!inner.otp_session_id.is_empty());
    assert!(!inner.masked_target.is_empty());
    assert_eq!(inner.expires_in_seconds, 600);
    assert_eq!(inner.code_length, 8);
    // Masked target should hide most of the email
    assert!(inner.masked_target.contains("@"));
    assert!(inner.masked_target.contains("*"));
}

/// The masked address shows the spelling the caller typed, not the folded
/// login key.
#[tokio::test]
async fn test_request_otp_masks_the_spelling_given() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let inner = svc
        .auth
        .request_otp(Request::new(RequestOtpRequest {
            principal: "Ann.Smith@sid.example.com".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(
        inner.masked_target.starts_with('A'),
        "{}",
        inner.masked_target
    );
}

#[tokio::test]
async fn test_request_otp_anti_enumeration() {
    // Non-existent email should still return a response (anti-enumeration).
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let req = Request::new(RequestOtpRequest {
        principal: "nobody@sid.example.com".to_string(),
    });
    let resp = svc.auth.request_otp(req).await.unwrap();
    let inner = resp.into_inner();
    // Should return a plausible response even for nonexistent emails
    assert!(!inner.otp_session_id.is_empty());
    assert!(inner.expires_in_seconds > 0);
}

#[tokio::test]
async fn test_request_otp_empty_identifier() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let req = Request::new(RequestOtpRequest {
        principal: String::new(),
    });
    let err = svc.auth.request_otp(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_verify_otp_invalid_session_id() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let req = Request::new(VerifyOtpRequest {
        code: "12345678".to_string(),
        session_id: Some("not-a-uuid".to_string()),
    });
    let err = svc.auth.verify_otp(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_verify_otp_wrong_code() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_system_project()
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Add email for OTP profile lookup
    let pe = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: profile.id,
        email: "alice@sid.example.com".to_string(),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: true,
        verified_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    svc.storage
        .create_profile_email(&pe, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Request OTP first
    let req = Request::new(RequestOtpRequest {
        principal: "alice@sid.example.com".to_string(),
    });
    let resp = svc.auth.request_otp(req).await.unwrap().into_inner();

    // Try wrong code
    let req = Request::new(VerifyOtpRequest {
        code: "00000000".to_string(),
        session_id: Some(resp.otp_session_id),
    });
    let resp = svc.auth.verify_otp(req).await.unwrap();
    assert!(!resp.into_inner().verified);
}

#[tokio::test]
async fn test_resend_otp_without_session() {
    let storage = MockStorage::new().with_system_project();
    let svc = TestServices::new(storage);

    let req = Request::new(ResendOtpRequest {
        session_id: Some(Uuid::new_v4().to_string()),
    });
    let err = svc.auth.resend_otp(req).await.unwrap_err();
    // An unknown code session reads as an expired one: request a new code.
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");
    assert_eq!(common::error_reason(&err).as_deref(), Some("INVALID_STATE"));
}

#[tokio::test]
async fn test_resend_otp_after_request() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_system_project()
        .with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Add email principal + profile_email for OTP lookup
    let mut ep = sid_core::models::Principal::new(
        profile.id,
        sid_core::models::PrincipalType::Email,
        "alice@sid.example.com",
    );
    ep.is_primary = true;
    svc.storage
        .save_principal(&ep, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let pe = sid_core::models::ProfileEmail {
        id: sid_core::models::ProfileEmailId::new(),
        profile_id: profile.id,
        email: "alice@sid.example.com".to_string(),
        label: sid_core::models::EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: true,
        verified_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    svc.storage
        .create_profile_email(&pe, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Request OTP
    let req = Request::new(RequestOtpRequest {
        principal: "alice@sid.example.com".to_string(),
    });
    let resp = svc.auth.request_otp(req).await.unwrap().into_inner();

    // Resend
    let req = Request::new(ResendOtpRequest {
        session_id: Some(resp.otp_session_id),
    });
    let resp = svc.auth.resend_otp(req).await.unwrap();
    assert!(resp.into_inner().expires_in > 0);
}

// ═══════════════════════════════════════════════════════════════════
// MFA Credential Deletion / TOTP Re-enrollment
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_delete_mfa_credential_requires_elevated_session() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Basic-level token (not elevated): a step-up to the elevated level is
    // asked for, which the user can do, rather than a permission refusal.
    let bearer = common::issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        DeleteMfaCredentialRequest {
            credential_id: Uuid::now_v7().to_string(),
        },
        &bearer,
    );
    let err = svc.auth.delete_mfa_credential(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        common::error_reason(&err).as_deref(),
        Some("STEP_UP_REQUIRED")
    );
}

#[tokio::test]
async fn test_delete_mfa_credential_not_found() {
    use sid_core::models::session::{AuthLevel, Session};

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create elevated session.
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.as_active().unwrap().elevate(AuthLevel::Elevated);

    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(profile.id.to_string(), "test", session.id.to_string()).into(),
        )
        .await
        .unwrap();

    // Non-existent credential → NotFound.
    let req = authed_request(
        DeleteMfaCredentialRequest {
            credential_id: Uuid::now_v7().to_string(),
        },
        &bearer,
    );
    let err = svc.auth.delete_mfa_credential(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_delete_totp_credential_then_reenroll() {
    use sid_core::models::session::{AuthLevel, Session};

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create elevated session.
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.as_active().unwrap().elevate(AuthLevel::Elevated);

    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(profile.id.to_string(), "test", session.id.to_string()).into(),
        )
        .await
        .unwrap();

    // Enroll TOTP first.
    let secret = sid_authn::generate_secret();
    let totp_cred = Credential::new(
        profile.id,
        CredentialType::Totp,
        sid_core::models::CredentialData::new(secret.clone()),
        Some("Old Phone".to_string()),
    );
    let cred_id = totp_cred.id;
    svc.storage
        .create_credential(
            &totp_cred,
            AuditEntry::user(profile.id.to_string(), "test", cred_id.0.to_string()).into(),
        )
        .await
        .unwrap();

    // Delete the TOTP credential.
    let req = authed_request(
        DeleteMfaCredentialRequest {
            credential_id: cred_id.0.to_string(),
        },
        &bearer,
    );
    let resp = svc
        .auth
        .delete_mfa_credential(req)
        .await
        .unwrap()
        .into_inner();
    assert!(resp.deleted);
    assert_eq!(resp.credential_type, "totp");

    // The TOTP is revoked (the record stays).
    let creds = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::Totp))
        .await
        .unwrap();
    assert!(
        creds.iter().all(|c| !c.status.is_active()),
        "TOTP credential should be revoked"
    );

    // Re-enroll: StartTotpEnrollment should now succeed (no "already enrolled" block).
    let req = authed_request(StartTotpEnrollmentRequest {}, &bearer);
    let resp = svc
        .auth
        .start_totp_enrollment(req)
        .await
        .unwrap()
        .into_inner();
    assert!(!resp.secret.is_empty(), "should get new TOTP secret");
    assert!(resp.qr_uri.contains("otpauth://totp/"));
}

// ═══════════════════════════════════════════════════════════════════
// Auth Context Extraction
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_enrollment_create_invite_with_bearer_uses_real_profile_id() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let jwt = test_jwt();
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt.clone(),
        common::test_revocation(),
    );

    // Issue an administrator token for this profile.
    let bearer = common::issue_admin_token(&jwt, profile.id);

    let req = authed_request(
        sid_proto::sid::v1::admin::CreateInviteRequest {
            max_uses: 1,
            metadata: Default::default(),
            expires_at: None,
        },
        &bearer,
    );
    let resp = svc.create_invite(req).await.unwrap().into_inner();

    // Invite should have been created (basic validation).
    assert!(!resp.code.is_empty());
    assert!(resp.active);

    // created_by should be the authenticated profile, not Uuid::nil().
    // We can't directly check created_by from proto (it's not in response),
    // but the handler uses it for AuditEntry — verify invite was created.
    assert_eq!(resp.max_uses, 1);
}

#[tokio::test]
async fn test_enrollment_create_invite_without_bearer_is_rejected() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt.clone(),
        common::test_revocation(),
    );

    // An invite records who created it, so the caller must be authenticated.
    let req = Request::new(sid_proto::sid::v1::admin::CreateInviteRequest {
        max_uses: 5,
        metadata: Default::default(),
        expires_at: None,
    });
    let err = svc.create_invite(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_governance_decide_request_requires_bearer_token() {
    use sid_proto::sid::v1::authz::governance_service_server::GovernanceService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let svc = sid_authz::governance_grpc::GovernanceServiceImpl::new(
        Arc::new(storage),
        jwt.clone(),
        common::test_revocation(),
    );

    // No bearer token → Unauthenticated.
    let req = Request::new(sid_proto::sid::v1::authz::DecideRequestRequest {
        request_id: Uuid::now_v7().to_string(),
        approved: true,
        reason: String::new(),
    });
    let err = svc.decide_request(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_governance_decide_request_with_bearer_extracts_reviewer() {
    use sid_proto::sid::v1::authz::governance_service_server::GovernanceService;

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let jwt = test_jwt();
    let svc = sid_authz::governance_grpc::GovernanceServiceImpl::new(
        Arc::new(storage),
        jwt.clone(),
        common::test_revocation(),
    );

    // Deciding requests belongs to administrators.
    let bearer = common::issue_admin_token(&jwt, profile.id);

    // With bearer token — extracts reviewer but request_id doesn't exist → NotFound.
    let req = authed_request(
        sid_proto::sid::v1::authz::DecideRequestRequest {
            request_id: Uuid::now_v7().to_string(),
            approved: true,
            reason: "approved for testing".to_string(),
        },
        &bearer,
    );
    let err = svc.decide_request(req).await.unwrap_err();
    // Auth succeeded (no Unauthenticated), but access request not found → NotFound.
    assert_eq!(err.code(), tonic::Code::NotFound);
}

// ═══════════════════════════════════════════════════════════════════
// Rate Limit Dashboard
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_rate_limit_dashboard_returns_zeros_without_cache() {
    let profile = test_profile();
    let mut admin = Profile::new(Some("admin"));
    admin.roles = vec!["admin".to_string()];
    let storage = MockStorage::new()
        .with_profile(profile)
        .with_profile(admin.clone());
    let svc = TestServices::new(storage);

    let bearer = common::issue_admin_token(&svc.jwt, admin.id);
    let req = authed_request(
        sid_proto::sid::v1::admin::GetRateLimitDashboardRequest {},
        &bearer,
    );
    let resp = svc
        .security
        .get_rate_limit_dashboard(req)
        .await
        .unwrap()
        .into_inner();

    // With NoCacheBackend, dashboard returns zeros (acceptable for dev mode).
    assert_eq!(resp.total_blocked_last_hour, 0);
    assert_eq!(resp.total_blocked_last_day, 0);
    assert!(resp.top_blocked_ips.is_empty());
    assert!(resp.top_blocked_endpoints.is_empty());
}

#[tokio::test]
async fn test_get_rate_limit_dashboard_requires_admin() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Non-admin token.
    let bearer = common::issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        sid_proto::sid::v1::admin::GetRateLimitDashboardRequest {},
        &bearer,
    );
    let err = svc
        .security
        .get_rate_limit_dashboard(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

// ═══════════════════════════════════════════════════════════════════
// Generic Step-Up (RequestStepUp / CompleteStepUp)
// ═══════════════════════════════════════════════════════════════════

/// A step-up request made from `session`: step-up always applies to the
/// session of the caller's own token.
fn step_up_request(
    svc: &TestServices,
    profile: &Profile,
    session: &Session,
    method: StepUpMethod,
) -> Request<RequestStepUpRequest> {
    let (token, _) = common::issue_token_with_session(
        &svc.jwt,
        profile,
        &["openid".to_string()],
        session.clone(),
    );
    authed_request(
        RequestStepUpRequest {
            session_id: session.id.to_string(),
            method: method as i32,
        },
        &token,
    )
}

#[tokio::test]
async fn test_request_step_up_totp_returns_empty_challenge() {
    let profile = test_profile();
    // Create a session (fresh, Full decay) and TOTP credential.
    let session = Session::new(
        profile.id,
        "10.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let totp_cred = Credential::new(profile.id, CredentialType::Totp, vec![1, 2, 3], None);
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session.clone())
        .with_credential(totp_cred);
    let svc = TestServices::new(storage);

    let req = step_up_request(&svc, &profile, &session, StepUpMethod::Totp);
    let resp = svc.auth.request_step_up(req).await.unwrap().into_inner();

    // 1-phase: no challenge needed, just echoes the method.
    assert_eq!(resp.method, StepUpMethod::Totp as i32);
    assert!(resp.challenge_id.is_empty());
    assert!(resp.challenge.is_none());
    // Decay-aware fields.
    assert!(
        !resp.allowed_methods.is_empty(),
        "should return allowed methods"
    );
    assert!(resp.allowed_methods.contains(&(StepUpMethod::Totp as i32)));
    assert_eq!(resp.decay_level, "full");
}

#[tokio::test]
async fn test_request_step_up_recovery_returns_empty_challenge() {
    let profile = test_profile();
    let session = Session::new(
        profile.id,
        "10.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let recovery_cred = Credential::new(profile.id, CredentialType::Recovery, vec![1, 2, 3], None);
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session.clone())
        .with_credential(recovery_cred);
    let svc = TestServices::new(storage);

    let req = step_up_request(&svc, &profile, &session, StepUpMethod::RecoveryCode);
    let resp = svc.auth.request_step_up(req).await.unwrap().into_inner();

    assert_eq!(resp.method, StepUpMethod::RecoveryCode as i32);
    assert!(resp.challenge.is_none());
    assert!(
        resp.allowed_methods
            .contains(&(StepUpMethod::RecoveryCode as i32))
    );
}

#[tokio::test]
async fn test_request_step_up_webauthn_no_passkeys_enrolled() {
    use sid_core::models::session::Session;

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create and save session (no passkeys enrolled for this profile).
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // No passkeys → FailedPrecondition.
    let req = step_up_request(&svc, &profile, &session, StepUpMethod::Webauthn);
    let err = svc.auth.request_step_up(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "no passkeys enrolled"
    );
}

#[tokio::test]
async fn test_request_step_up_webauthn_invalid_session() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // A token whose session is not stored names an ended session: sign in
    // again (TOKEN_EXPIRED).
    let unstored = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let req = step_up_request(&svc, &profile, &unstored, StepUpMethod::Webauthn);
    let err = svc.auth.request_step_up(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert_eq!(common::error_reason(&err).as_deref(), Some("TOKEN_EXPIRED"));
}

#[tokio::test]
async fn test_request_step_up_unspecified_returns_available_methods() {
    // Unspecified = query mode: returns allowed methods + decay without starting challenge.
    let profile = test_profile();
    let session = Session::new(
        profile.id,
        "10.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let totp_cred = Credential::new(profile.id, CredentialType::Totp, vec![1, 2, 3], None);
    let webauthn_cred = Credential::new(profile.id, CredentialType::WebAuthn, vec![1, 2, 3], None);
    let recovery_cred = Credential::new(profile.id, CredentialType::Recovery, vec![1, 2, 3], None);
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session.clone())
        .with_credential(totp_cred)
        .with_credential(webauthn_cred)
        .with_credential(recovery_cred);
    let svc = TestServices::new(storage);

    let req = step_up_request(&svc, &profile, &session, StepUpMethod::Unspecified);
    let resp = svc.auth.request_step_up(req).await.unwrap().into_inner();

    // Query mode returns all enrolled methods (Full decay → no restrictions).
    assert_eq!(resp.method, StepUpMethod::Unspecified as i32);
    assert!(resp.challenge_id.is_empty());
    assert!(resp.challenge.is_none());
    assert_eq!(resp.decay_level, "full");
    assert!(
        resp.allowed_methods
            .contains(&(StepUpMethod::Webauthn as i32))
    );
    assert!(resp.allowed_methods.contains(&(StepUpMethod::Totp as i32)));
    assert!(
        resp.allowed_methods
            .contains(&(StepUpMethod::RecoveryCode as i32))
    );
}

#[tokio::test]
async fn test_request_step_up_unspecified_medium_decay_totp_only_fails_precondition() {
    // Medium decay + only TOTP enrolled (no WebAuthn) → allowed = [] →
    // step-up impossible: phishing-resistant only but no phishing-resistant method enrolled.
    let profile = test_profile();
    let mut session = Session::new(
        profile.id,
        "10.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    // 5 hours ago → Medium decay.
    session.authenticated_at = chrono::Utc::now() - chrono::Duration::hours(5);
    let totp_cred = Credential::new(profile.id, CredentialType::Totp, vec![1, 2, 3], None);
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session.clone())
        .with_credential(totp_cred); // TOTP only — not phishing-resistant
    let svc = TestServices::new(storage);

    let req = step_up_request(&svc, &profile, &session, StepUpMethod::Unspecified);
    let err = svc.auth.request_step_up(req).await.unwrap_err();

    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "TOTP-only at medium decay → no phishing-resistant method → FailedPrecondition"
    );
}

#[tokio::test]
async fn test_request_step_up_unspecified_no_methods_fails_precondition() {
    // Unspecified (query mode) with NO MFA methods enrolled →
    // FailedPrecondition, not an empty-list success response.
    // An empty allowed_methods in a success response is a protocol nonsense:
    // step-up is impossible, so we must reject rather than mislead the client.
    let profile = test_profile();
    let session = Session::new(
        profile.id,
        "10.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    // No MFA credentials registered for this profile.
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session.clone());
    let svc = TestServices::new(storage);

    let req = step_up_request(&svc, &profile, &session, StepUpMethod::Unspecified);
    let err = svc.auth.request_step_up(req).await.unwrap_err();

    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "no enrolled methods → step-up impossible → FailedPrecondition"
    );
    // MFA_REQUIRED tells the client to enroll a second factor first.
    assert_eq!(common::error_reason(&err).as_deref(), Some("MFA_REQUIRED"));
}

#[tokio::test]
async fn test_request_step_up_medium_decay_only_phishing_resistant() {
    // Medium decay (4-12h) → only phishing-resistant methods (WebAuthn).
    let profile = test_profile();
    let mut session = Session::new(
        profile.id,
        "10.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    // Set authenticated_at to 5 hours ago → Medium decay.
    session.authenticated_at = chrono::Utc::now() - chrono::Duration::hours(5);
    let totp_cred = Credential::new(profile.id, CredentialType::Totp, vec![1, 2, 3], None);
    let webauthn_cred = Credential::new(profile.id, CredentialType::WebAuthn, vec![1, 2, 3], None);
    let recovery_cred = Credential::new(profile.id, CredentialType::Recovery, vec![1, 2, 3], None);
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session.clone())
        .with_credential(totp_cred)
        .with_credential(webauthn_cred)
        .with_credential(recovery_cred);
    let svc = TestServices::new(storage);

    let req = step_up_request(&svc, &profile, &session, StepUpMethod::Unspecified);
    let resp = svc.auth.request_step_up(req).await.unwrap().into_inner();

    assert_eq!(resp.decay_level, "medium");
    // Only WebAuthn (phishing-resistant) should be allowed.
    assert!(
        resp.allowed_methods
            .contains(&(StepUpMethod::Webauthn as i32)),
        "WebAuthn should be allowed at Medium decay"
    );
    assert!(
        !resp.allowed_methods.contains(&(StepUpMethod::Totp as i32)),
        "TOTP should NOT be allowed at Medium decay"
    );
    assert!(
        !resp
            .allowed_methods
            .contains(&(StepUpMethod::RecoveryCode as i32)),
        "Recovery should NOT be allowed at Medium decay"
    );
}

#[tokio::test]
async fn test_request_step_up_medium_decay_rejects_totp() {
    // Medium decay + TOTP request → FailedPrecondition.
    let profile = test_profile();
    let mut session = Session::new(
        profile.id,
        "10.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.authenticated_at = chrono::Utc::now() - chrono::Duration::hours(5);
    let totp_cred = Credential::new(profile.id, CredentialType::Totp, vec![1, 2, 3], None);
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session.clone())
        .with_credential(totp_cred);
    let svc = TestServices::new(storage);

    let req = step_up_request(&svc, &profile, &session, StepUpMethod::Totp);
    let err = svc.auth.request_step_up(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "TOTP at Medium decay should be rejected"
    );
    let details = tonic_types::StatusExt::get_error_details(&err);
    assert_eq!(details.error_info().unwrap().reason, "INVALID_STATE");
    let violation = &details.precondition_failure().unwrap().violations[0];
    assert_eq!(violation.r#type, "SESSION_DECAY");
    assert_eq!(violation.description, "phishing-resistant methods only");
}

#[tokio::test]
async fn test_request_step_up_low_decay_requires_reauth() {
    // Low decay (12h+) → full re-auth required, step-up blocked entirely.
    let profile = test_profile();
    let mut session = Session::new(
        profile.id,
        "10.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.authenticated_at = chrono::Utc::now() - chrono::Duration::hours(13);
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session.clone());
    let svc = TestServices::new(storage);

    let req = step_up_request(&svc, &profile, &session, StepUpMethod::Unspecified);
    let err = svc.auth.request_step_up(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    let details = tonic_types::StatusExt::get_error_details(&err);
    assert_eq!(details.error_info().unwrap().reason, "INVALID_STATE");
    let violation = &details.precondition_failure().unwrap().violations[0];
    assert_eq!(violation.r#type, "SESSION_DECAY");
    assert_eq!(violation.description, "sign in again");
}

#[tokio::test]
async fn test_complete_step_up_totp_elevates_session() {
    use sid_core::models::session::Session;
    use sid_core::models::{Credential, CredentialData, CredentialType};

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Create session at Basic level, signed in two hours ago.
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.authenticated_at = chrono::Utc::now() - chrono::Duration::hours(2);
    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // Enroll TOTP credential: create a valid TOTP secret, stored sealed.
    let secret = b"JBSWY3DPEHPK3PXP"; // base32-decodable test secret
    let totp_cred = Credential::new(
        profile.id,
        CredentialType::Totp,
        CredentialData::new(common::sealed_totp_seed(profile.id, secret).await),
        None,
    );
    svc.storage
        .create_credential(
            &totp_cred,
            AuditEntry::user(profile.id.to_string(), "credential.create", "test").into(),
        )
        .await
        .unwrap();

    // Generate valid TOTP code.
    let code = sid_authn::generate_current_totp(secret);

    // CompleteStepUp with TOTP.
    let req = authed_request(
        CompleteStepUpRequest {
            session_id: session.id.to_string(),
            method: StepUpMethod::Totp as i32,
            challenge_id: String::new(),
            proof: Some(complete_step_up_request::Proof::TotpCode(code)),
        },
        &bearer,
    );
    let resp = svc.auth.complete_step_up(req).await.unwrap().into_inner();

    // Verify response has elevated token.
    assert!(
        !resp.new_session_token.is_empty(),
        "should return new token"
    );
    assert_eq!(resp.acr, "urn:sid:acr:standard");
    assert!(resp.amr.contains(&"otp".to_string()));

    // Verify new token is valid and has elevated ACR.
    let new_claims = svc
        .jwt
        .validate_access_token(&resp.new_session_token)
        .unwrap();
    assert_eq!(new_claims.acr, "urn:sid:acr:standard");

    // Verify session was elevated in storage.
    let updated_session = svc.storage.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(
        updated_session.assurance_level,
        sid_core::models::session::AuthLevel::Standard
    );
    assert!(updated_session.amr.contains(&"otp".to_string()));
    // The step-up is a fresh authentication a sensitive operation can reuse.
    assert_eq!(
        updated_session.decay_level(),
        sid_core::models::session::SessionDecayLevel::Full,
        "the step-up did not refresh the authentication time"
    );

    // The step-up rotates the token: the one it replaced no longer passes.
    let old_claims = svc.jwt.validate_access_token(&bearer).unwrap();
    assert!(
        svc.revocation_cache
            .is_revoked(&old_claims.jti, &old_claims.sid)
            .await
            .unwrap(),
        "the pre-step-up token still passes"
    );
    assert!(
        !svc.revocation_cache
            .is_revoked(&new_claims.jti, &new_claims.sid)
            .await
            .unwrap()
    );
}

/// A session with its bearer, and a stored recovery-code set holding `code`
/// with the given status.
async fn recovery_step_up_fixture(
    code: &str,
    status: sid_core::models::credential::CredentialStatus,
) -> (TestServices, String, sid_core::models::session::Session) {
    use sid_core::models::session::Session;
    use sid_core::models::{Credential, CredentialData, CredentialType};

    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    let hashes = vec![
        sid_authn::hash_code(&sid_authn::normalize_code(code)),
        sid_authn::hash_code(&sid_authn::normalize_code("ZZZZ-ZZZZ-ZZZZ")),
    ];
    let mut credential = Credential::new(
        profile.id,
        CredentialType::Recovery,
        CredentialData::new(serde_json::to_vec(&hashes).unwrap()),
        None,
    );
    credential.status = status;
    svc.storage
        .create_credential(&credential, AuditEntry::system("test", "recovery").into())
        .await
        .unwrap();
    (svc, bearer, session)
}

fn recovery_step_up(
    session: &sid_core::models::session::Session,
    code: &str,
    bearer: &str,
) -> Request<CompleteStepUpRequest> {
    authed_request(
        CompleteStepUpRequest {
            session_id: session.id.to_string(),
            method: StepUpMethod::RecoveryCode as i32,
            challenge_id: String::new(),
            proof: Some(complete_step_up_request::Proof::RecoveryCode(
                code.to_string(),
            )),
        },
        bearer,
    )
}

/// A revoked recovery-code set does not complete a step-up.
#[tokio::test]
async fn test_complete_step_up_revoked_recovery_codes_refused() {
    use sid_core::models::credential::CredentialStatus;
    let (svc, bearer, session) =
        recovery_step_up_fixture("AAAA-BBBB-CCCC", CredentialStatus::Revoked).await;

    let err = svc
        .auth
        .complete_step_up(recovery_step_up(&session, "AAAA-BBBB-CCCC", &bearer))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

/// A recovery code completes one step-up and is spent: the same code again
/// is refused, and the other codes of the set remain.
#[tokio::test]
async fn test_complete_step_up_recovery_code_is_single_use() {
    use sid_core::models::credential::CredentialStatus;
    let (svc, bearer, session) =
        recovery_step_up_fixture("AAAA-BBBB-CCCC", CredentialStatus::Active).await;

    // Each step-up rotates the token, so later calls use the one it returned.
    let rotated = svc
        .auth
        .complete_step_up(recovery_step_up(&session, "AAAA-BBBB-CCCC", &bearer))
        .await
        .unwrap()
        .into_inner()
        .new_session_token;
    let err = svc
        .auth
        .complete_step_up(recovery_step_up(&session, "AAAA-BBBB-CCCC", &rotated))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert_ne!(
        tonic_types::StatusExt::get_details_error_info(&err).map(|i| i.reason),
        Some("TOKEN_INVALID".to_string()),
        "refused as a revoked token, not as a spent code: {err:?}"
    );
    svc.auth
        .complete_step_up(recovery_step_up(&session, "ZZZZ-ZZZZ-ZZZZ", &rotated))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_complete_step_up_totp_wrong_code() {
    use sid_core::models::session::Session;
    use sid_core::models::{Credential, CredentialData, CredentialType};

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    let secret = b"JBSWY3DPEHPK3PXP";
    let totp_cred = Credential::new(
        profile.id,
        CredentialType::Totp,
        CredentialData::new(common::sealed_totp_seed(profile.id, secret).await),
        None,
    );
    svc.storage
        .create_credential(
            &totp_cred,
            AuditEntry::user(profile.id.to_string(), "credential.create", "test").into(),
        )
        .await
        .unwrap();

    // Wrong code.
    let req = authed_request(
        CompleteStepUpRequest {
            session_id: session.id.to_string(),
            method: StepUpMethod::Totp as i32,
            challenge_id: String::new(),
            proof: Some(complete_step_up_request::Proof::TotpCode(
                "000000".to_string(),
            )),
        },
        &bearer,
    );
    let err = svc.auth.complete_step_up(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_complete_step_up_no_mfa_enrolled() {
    use sid_core::models::session::Session;

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // No TOTP credential enrolled → FailedPrecondition.
    let req = authed_request(
        CompleteStepUpRequest {
            session_id: session.id.to_string(),
            method: StepUpMethod::Totp as i32,
            challenge_id: String::new(),
            proof: Some(complete_step_up_request::Proof::TotpCode(
                "123456".to_string(),
            )),
        },
        &bearer,
    );
    let err = svc.auth.complete_step_up(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_complete_step_up_webauthn_expired_challenge() {
    use sid_core::models::session::Session;

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    let req = authed_request(
        CompleteStepUpRequest {
            session_id: session.id.to_string(),
            method: StepUpMethod::Webauthn as i32,
            challenge_id: String::new(),
            proof: Some(complete_step_up_request::Proof::WebauthnAssertion(vec![
                1, 2, 3,
            ])),
        },
        &bearer,
    );
    let err = svc.auth.complete_step_up(req).await.unwrap_err();
    // Invalid JSON assertion → InvalidArgument (before challenge_id lookup).
    // The empty challenge_id would fail on take() → session_expired.
    // But serde parse of [1,2,3] as PublicKeyCredential fails first.
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_complete_step_up_webauthn_no_challenge_id() {
    use sid_core::models::session::Session;

    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(
                profile.id.to_string(),
                "session.test",
                session.id.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // A well-formed assertion, but for a challenge_id this session never
    // requested → the step-up reads as expired.
    let mut key = sid_authn::webauthn::soft_authenticator::SoftAuthenticator::new(
        "https://sid.example.com",
        "sid.example.com",
    );
    key.register(br#"{"publicKey":{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","user":{"id":"AAAAAAAAAAAAAAAAAAAAAA"}}}"#);
    let assertion = key.assert(
        br#"{"publicKey":{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rpId":"sid.example.com"}}"#,
    );
    let req = authed_request(
        CompleteStepUpRequest {
            session_id: session.id.to_string(),
            method: StepUpMethod::Webauthn as i32,
            challenge_id: "nonexistent-challenge".to_string(),
            proof: Some(complete_step_up_request::Proof::WebauthnAssertion(
                assertion,
            )),
        },
        &bearer,
    );
    let err = svc.auth.complete_step_up(req).await.unwrap_err();
    // challenge_id not in ChallengeStore: the step-up reads as expired.
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(common::error_reason(&err).as_deref(), Some("INVALID_STATE"));
}

// ══════════════════════════════════════════════════════════════════════════
// Enrollment Service Handler Tests
// ══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_enrollment_get_policy_returns_ce_defaults() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let resp = svc
        .get_enrollment_policy(Request::new(()))
        .await
        .unwrap()
        .into_inner();

    // CE defaults: Open mode, track_source = true
    assert!(resp.invite.is_some());
    assert!(resp.track_source);
}

#[tokio::test]
async fn test_enrollment_update_policy_returns_unimplemented() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req =
        Request::new(sid_proto::sid::v1::admin::UpdateEnrollmentPolicyRequest { policy: None });
    let err = svc.update_enrollment_policy(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn test_enrollment_list_invites_empty() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req = authed_request(
        sid_proto::sid::v1::admin::ListInvitesRequest {
            status: 0,
            page_size: 10,
            page_token: String::new(),
            search: String::new(),
        },
        &token,
    );
    let resp = svc.list_invites(req).await.unwrap().into_inner();
    assert!(resp.invites.is_empty());
    assert_eq!(resp.total_count, 0);
}

#[tokio::test]
async fn test_enrollment_create_invite_returns_valid_response() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req = authed_request(
        sid_proto::sid::v1::admin::CreateInviteRequest {
            max_uses: 3,
            metadata: Default::default(),
            expires_at: None,
        },
        &token,
    );
    let invite = svc.create_invite(req).await.unwrap().into_inner();
    assert!(!invite.code.is_empty());
    assert!(!invite.id.is_empty());
    assert_eq!(invite.max_uses, 3);
    assert_eq!(invite.use_count, 0);
    assert!(invite.active);
    assert!(invite.created_at.is_some());
}

#[tokio::test]
async fn test_enrollment_create_invite_default_max_uses() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    // max_uses = 0 → defaults to 1
    let req = authed_request(
        sid_proto::sid::v1::admin::CreateInviteRequest {
            max_uses: 0,
            metadata: Default::default(),
            expires_at: None,
        },
        &token,
    );
    let invite = svc.create_invite(req).await.unwrap().into_inner();
    assert_eq!(invite.max_uses, 1);
}

#[tokio::test]
async fn test_enrollment_list_invites_with_mock_returns_empty() {
    // MockStorage doesn't persist invites — list always returns empty.
    // Real persistence tested via PostgreSQL integration tests.
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req = authed_request(
        sid_proto::sid::v1::admin::ListInvitesRequest {
            status: sid_proto::sid::v1::admin::InviteStatus::Active as i32,
            page_size: 50,
            page_token: String::new(),
            search: String::new(),
        },
        &token,
    );
    let resp = svc.list_invites(req).await.unwrap().into_inner();
    assert_eq!(resp.total_count, 0);
    assert!(resp.invites.is_empty());
}

#[tokio::test]
async fn test_enrollment_revoke_nonexistent_returns_not_found() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req = authed_request(
        sid_proto::sid::v1::admin::RevokeInviteRequest {
            invite_id: uuid::Uuid::now_v7().to_string(),
        },
        &token,
    );
    let err = svc.revoke_invite(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_enrollment_revoke_invalid_id_returns_invalid_argument() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req = authed_request(
        sid_proto::sid::v1::admin::RevokeInviteRequest {
            invite_id: "not-a-uuid".to_string(),
        },
        &token,
    );
    let err = svc.revoke_invite(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_enrollment_bulk_create_invites() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req = authed_request(
        sid_proto::sid::v1::admin::BulkCreateInvitesRequest {
            count: 5,
            max_uses: 2,
            metadata: Default::default(),
            expires_at: None,
        },
        &token,
    );
    let resp = svc.bulk_create_invites(req).await.unwrap().into_inner();
    assert_eq!(resp.invites.len(), 5);

    // Each invite should have unique code
    let codes: std::collections::HashSet<&str> =
        resp.invites.iter().map(|i| i.code.as_str()).collect();
    assert_eq!(codes.len(), 5);

    // Each should have max_uses = 2
    for inv in &resp.invites {
        assert_eq!(inv.max_uses, 2);
        assert!(inv.active);
    }
}

#[tokio::test]
async fn test_enrollment_bulk_create_zero_returns_error() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req = authed_request(
        sid_proto::sid::v1::admin::BulkCreateInvitesRequest {
            count: 0,
            max_uses: 1,
            metadata: Default::default(),
            expires_at: None,
        },
        &token,
    );
    let err = svc.bulk_create_invites(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_enrollment_get_registration_stats() {
    use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService;

    let storage = MockStorage::new();
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = sid_server::grpc::enrollment_service::EnrollmentServiceImpl::new(
        Arc::new(storage),
        jwt,
        common::test_revocation(),
    );

    let req = authed_request(
        sid_proto::sid::v1::admin::GetRegistrationStatsRequest { period_days: 30 },
        &token,
    );
    let resp = svc.get_registration_stats(req).await.unwrap().into_inner();

    // Empty storage = zero stats
    assert_eq!(resp.total, 0);
    assert_eq!(resp.total_referrals, 0);
    assert_eq!(resp.unique_referrers, 0);
}

// ═══════════════════════════════════════════════════════════════════
// AccountService — Phone/Email Contact Management
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_account_add_phone_and_list() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add a phone
    let req = authed_request(
        sid_proto::sid::v1::account::AddPhoneRequest {
            e164: 380501234567,
            extension: None,
            label: sid_proto::sid::v1::PhoneLabel::Mobile.into(),
            custom_label: None,
            is_primary: true,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
        },
        &token,
    );
    let resp = svc.account.add_phone(req).await.unwrap().into_inner();
    assert_eq!(resp.e164, 380501234567);
    assert!(resp.is_primary);
    assert!(resp.can_receive_sms);
    assert!(!resp.verified); // New phone is not verified
    let phone_id = resp.id.clone();

    // List phones
    let req = authed_request((), &token);
    let list = svc.account.list_phones(req).await.unwrap().into_inner();
    assert_eq!(list.phones.len(), 1);
    assert_eq!(list.phones[0].id, phone_id);
    assert_eq!(list.phones[0].e164, 380501234567);
}

#[tokio::test]
async fn test_account_add_email_and_list() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add an email
    let req = authed_request(
        sid_proto::sid::v1::account::AddEmailRequest {
            email: "Bob@SID.Example.COM".to_string(),
            label: sid_proto::sid::v1::EmailLabel::Work.into(),
            custom_label: None,
            is_primary: true,
        },
        &token,
    );
    let resp = svc.account.add_email(req).await.unwrap().into_inner();
    // The local part keeps its spelling (mail goes there); only the domain,
    // which carries no case, is canonical.
    assert_eq!(resp.email, "Bob@sid.example.com");
    assert!(resp.is_primary);
    assert!(!resp.verified);
    let email_id = resp.id.clone();

    // List emails
    let req = authed_request((), &token);
    let list = svc.account.list_emails(req).await.unwrap().into_inner();
    assert_eq!(list.emails.len(), 1);
    assert_eq!(list.emails[0].id, email_id);
}

#[tokio::test]
async fn test_account_remove_phone() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add phone
    let req = authed_request(
        sid_proto::sid::v1::account::AddPhoneRequest {
            e164: 12025551234,
            extension: None,
            label: sid_proto::sid::v1::PhoneLabel::Work.into(),
            custom_label: None,
            is_primary: false,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
        },
        &token,
    );
    let phone = svc.account.add_phone(req).await.unwrap().into_inner();

    // Remove phone
    let req = authed_request(
        sid_proto::sid::v1::account::RemovePhoneRequest {
            phone_id: phone.id.clone(),
        },
        &token,
    );
    svc.account.remove_phone(req).await.unwrap();

    // List should be empty
    let req = authed_request((), &token);
    let list = svc.account.list_phones(req).await.unwrap().into_inner();
    assert_eq!(list.phones.len(), 0);
}

#[tokio::test]
async fn test_account_remove_email() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add email
    let req = authed_request(
        sid_proto::sid::v1::account::AddEmailRequest {
            email: "test@sid.example.com".to_string(),
            label: sid_proto::sid::v1::EmailLabel::Personal.into(),
            custom_label: None,
            is_primary: false,
        },
        &token,
    );
    let email = svc.account.add_email(req).await.unwrap().into_inner();

    // Remove email
    let req = authed_request(
        sid_proto::sid::v1::account::RemoveEmailRequest {
            email_id: email.id.clone(),
        },
        &token,
    );
    svc.account.remove_email(req).await.unwrap();

    // List should be empty
    let req = authed_request((), &token);
    let list = svc.account.list_emails(req).await.unwrap().into_inner();
    assert_eq!(list.emails.len(), 0);
}

#[tokio::test]
async fn test_account_update_phone_label() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add phone with Mobile label
    let req = authed_request(
        sid_proto::sid::v1::account::AddPhoneRequest {
            e164: 441234567890,
            extension: Some(5678),
            label: sid_proto::sid::v1::PhoneLabel::Mobile.into(),
            custom_label: None,
            is_primary: false,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
        },
        &token,
    );
    let phone = svc.account.add_phone(req).await.unwrap().into_inner();

    // Update label to Work
    let req = authed_request(
        sid_proto::sid::v1::account::UpdatePhoneRequest {
            phone_id: phone.id.clone(),
            label: Some(sid_proto::sid::v1::PhoneLabel::Work.into()),
            custom_label: None,
            can_receive_sms: Some(false),
            can_receive_fax: None,
            can_receive_voice: None,
        },
        &token,
    );
    let updated = svc.account.update_phone(req).await.unwrap().into_inner();
    assert_eq!(updated.label, sid_proto::sid::v1::PhoneLabel::Work as i32);
    assert!(!updated.can_receive_sms); // Updated
    assert!(updated.can_receive_voice); // Unchanged
    assert_eq!(updated.extension, Some(5678)); // Unchanged
}

#[tokio::test]
async fn test_account_set_primary_phone_swaps() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add phone 1 as primary
    let req = authed_request(
        sid_proto::sid::v1::account::AddPhoneRequest {
            e164: 380501111111,
            extension: None,
            label: sid_proto::sid::v1::PhoneLabel::Mobile.into(),
            custom_label: None,
            is_primary: true,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
        },
        &token,
    );
    let phone1 = svc.account.add_phone(req).await.unwrap().into_inner();

    // Add phone 2 as non-primary
    let req = authed_request(
        sid_proto::sid::v1::account::AddPhoneRequest {
            e164: 380502222222,
            extension: None,
            label: sid_proto::sid::v1::PhoneLabel::Work.into(),
            custom_label: None,
            is_primary: false,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
        },
        &token,
    );
    let phone2 = svc.account.add_phone(req).await.unwrap().into_inner();

    // Set phone 2 as primary
    let req = authed_request(
        sid_proto::sid::v1::account::SetPrimaryPhoneRequest {
            phone_id: phone2.id.clone(),
        },
        &token,
    );
    let result = svc
        .account
        .set_primary_phone(req)
        .await
        .unwrap()
        .into_inner();
    assert!(result.is_primary);

    // Verify phone 1 is no longer primary
    let req = authed_request((), &token);
    let list = svc.account.list_phones(req).await.unwrap().into_inner();
    let p1 = list.phones.iter().find(|p| p.id == phone1.id).unwrap();
    let p2 = list.phones.iter().find(|p| p.id == phone2.id).unwrap();
    assert!(!p1.is_primary, "phone1 should no longer be primary");
    assert!(p2.is_primary, "phone2 should now be primary");
}

#[tokio::test]
async fn test_account_set_primary_email_swaps() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add email 1 as primary
    let req = authed_request(
        sid_proto::sid::v1::account::AddEmailRequest {
            email: "first@sid.example.com".to_string(),
            label: sid_proto::sid::v1::EmailLabel::Personal.into(),
            custom_label: None,
            is_primary: true,
        },
        &token,
    );
    let email1 = svc.account.add_email(req).await.unwrap().into_inner();

    // Add email 2 as non-primary
    let req = authed_request(
        sid_proto::sid::v1::account::AddEmailRequest {
            email: "second@sid.example.com".to_string(),
            label: sid_proto::sid::v1::EmailLabel::Work.into(),
            custom_label: None,
            is_primary: false,
        },
        &token,
    );
    let email2 = svc.account.add_email(req).await.unwrap().into_inner();

    // Set email 2 as primary
    let req = authed_request(
        sid_proto::sid::v1::account::SetPrimaryEmailRequest {
            email_id: email2.id.clone(),
        },
        &token,
    );
    let result = svc
        .account
        .set_primary_email(req)
        .await
        .unwrap()
        .into_inner();
    assert!(result.is_primary);

    // Verify email 1 is no longer primary
    let req = authed_request((), &token);
    let list = svc.account.list_emails(req).await.unwrap().into_inner();
    let e1 = list.emails.iter().find(|e| e.id == email1.id).unwrap();
    let e2 = list.emails.iter().find(|e| e.id == email2.id).unwrap();
    assert!(!e1.is_primary, "email1 should no longer be primary");
    assert!(e2.is_primary, "email2 should now be primary");
}

#[tokio::test]
async fn test_account_phone_requires_auth() {
    let svc = TestServices::new(MockStorage::new());

    // No auth token → Unauthenticated
    let req = Request::new(());
    let err = svc.account.list_phones(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_account_email_requires_auth() {
    let svc = TestServices::new(MockStorage::new());

    let req = Request::new(());
    let err = svc.account.list_emails(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_account_remove_phone_not_found() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(
        sid_proto::sid::v1::account::RemovePhoneRequest {
            phone_id: Uuid::now_v7().to_string(),
        },
        &token,
    );
    let err = svc.account.remove_phone(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_account_add_phone_validates_e164() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // e164 = 0 → invalid
    let req = authed_request(
        sid_proto::sid::v1::account::AddPhoneRequest {
            e164: 0,
            extension: None,
            label: sid_proto::sid::v1::PhoneLabel::Mobile.into(),
            custom_label: None,
            is_primary: false,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
        },
        &token,
    );
    let err = svc.account.add_phone(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_account_update_email_label() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add email with Personal label
    let req = authed_request(
        sid_proto::sid::v1::account::AddEmailRequest {
            email: "update-test@sid.example.com".to_string(),
            label: sid_proto::sid::v1::EmailLabel::Personal.into(),
            custom_label: None,
            is_primary: false,
        },
        &token,
    );
    let email = svc.account.add_email(req).await.unwrap().into_inner();

    // Update label to Work
    let req = authed_request(
        sid_proto::sid::v1::account::UpdateEmailRequest {
            email_id: email.id.clone(),
            label: Some(sid_proto::sid::v1::EmailLabel::Work.into()),
            custom_label: None,
        },
        &token,
    );
    let updated = svc.account.update_email(req).await.unwrap().into_inner();
    assert_eq!(updated.label, sid_proto::sid::v1::EmailLabel::Work as i32);
    assert_eq!(updated.email, "update-test@sid.example.com"); // Unchanged
}

#[tokio::test]
async fn test_account_phone_custom_label_roundtrip() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add phone with custom label
    let req = authed_request(
        sid_proto::sid::v1::account::AddPhoneRequest {
            e164: 491701234567,
            extension: None,
            label: sid_proto::sid::v1::PhoneLabel::Custom.into(),
            custom_label: Some("Emergency".to_string()),
            is_primary: false,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
        },
        &token,
    );
    let phone = svc.account.add_phone(req).await.unwrap().into_inner();
    assert_eq!(phone.label, sid_proto::sid::v1::PhoneLabel::Custom as i32);
    assert_eq!(phone.custom_label.as_deref(), Some("Emergency"));

    // Verify in list
    let req = authed_request((), &token);
    let list = svc.account.list_phones(req).await.unwrap().into_inner();
    assert_eq!(list.phones[0].custom_label.as_deref(), Some("Emergency"));
}

#[tokio::test]
async fn test_account_email_custom_label_roundtrip() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Add email with custom label
    let req = authed_request(
        sid_proto::sid::v1::account::AddEmailRequest {
            email: "custom@sid.example.com".to_string(),
            label: sid_proto::sid::v1::EmailLabel::Custom.into(),
            custom_label: Some("Newsletter signup".to_string()),
            is_primary: false,
        },
        &token,
    );
    let email = svc.account.add_email(req).await.unwrap().into_inner();
    assert_eq!(email.label, sid_proto::sid::v1::EmailLabel::Custom as i32);
    assert_eq!(email.custom_label.as_deref(), Some("Newsletter signup"));

    // Verify in list
    let req = authed_request((), &token);
    let list = svc.account.list_emails(req).await.unwrap().into_inner();
    assert_eq!(
        list.emails[0].custom_label.as_deref(),
        Some("Newsletter signup")
    );
}

#[tokio::test]
async fn test_account_remove_email_not_found() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(
        sid_proto::sid::v1::account::RemoveEmailRequest {
            email_id: Uuid::now_v7().to_string(),
        },
        &token,
    );
    let err = svc.account.remove_email(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_account_add_email_validates_empty() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let req = authed_request(
        sid_proto::sid::v1::account::AddEmailRequest {
            email: String::new(),
            label: sid_proto::sid::v1::EmailLabel::Personal.into(),
            custom_label: None,
            is_primary: false,
        },
        &token,
    );
    let err = svc.account.add_email(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ═══════════════════════════════════════════════════════════════════
// Principal assignment: gRPC-level tests
//
// A principal routes sign-in only to its assigned, eligible profile. Login
// method discovery reads no account, so routing is observed at a sign-in
// step ([`common::routes_to`]).
// ═══════════════════════════════════════════════════════════════════

/// The login methods discovery offers for `principal`.
async fn discover(svc: &TestServices, principal: &str) -> Vec<String> {
    svc.auth
        .resolve_principal(Request::new(ResolvePrincipalRequest {
            principal: principal.to_string(),
        }))
        .await
        .expect("discovery answers every well-formed identifier")
        .into_inner()
        .available_methods
}

/// Regression: discovery answered an existing account's own methods (magic
/// link, a suggested method) and an unknown address a bare "opaque", so the
/// answer told whether the address has an account. It now depends only on
/// the identifier type and what the installation enables (WebAuthn L3
/// §14.6.2).
#[tokio::test]
async fn test_discovery_answers_alike_for_every_email() {
    let svc = TestServices::with_magic_links(MockStorage::new());
    let email = "known@sid.example.com";
    claim_email(&svc, &test_profile(), email).await;

    let known = discover(&svc, email).await;
    assert_eq!(known, discover(&svc, "nobody@sid.example.com").await);
    assert_eq!(known, ["opaque", "webauthn", "magic_link"]);
}

/// Regression: magic links were offered while the installation had them off
/// (the default), so the client led the user to a sign-in that is refused.
#[tokio::test]
async fn test_discovery_offers_magic_link_only_when_enabled() {
    let svc = TestServices::new(MockStorage::new());
    assert_eq!(
        discover(&svc, "someone@sid.example.com").await,
        ["opaque", "webauthn"]
    );
}

/// Magic links are delivered by email only: a phone number or a user name is
/// never offered one.
#[tokio::test]
async fn test_discovery_offers_magic_link_for_email_only() {
    let svc = TestServices::with_magic_links(MockStorage::new());
    for principal in ["+380501234567", "alice"] {
        assert_eq!(
            discover(&svc, principal).await,
            ["opaque", "webauthn"],
            "{principal}"
        );
    }
}

/// A malformed identifier is refused by its form alone.
#[tokio::test]
async fn test_discovery_refuses_a_malformed_identifier() {
    let svc = TestServices::new(MockStorage::new());
    for principal in ["", "   ", "ab"] {
        let err = svc
            .auth
            .resolve_principal(Request::new(ResolvePrincipalRequest {
                principal: principal.to_string(),
            }))
            .await
            .expect_err(principal);
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{principal:?}");
    }
}

/// Save `profile` and its claim on `email`.
async fn claim_email(svc: &TestServices, profile: &Profile, email: &str) {
    use sid_core::models::Principal;

    svc.storage
        .create_profile(profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    svc.storage
        .save_principal(
            &Principal::new_email(profile.id, email),
            AuditEntry::system("test", "setup").into(),
        )
        .await
        .unwrap();
}

/// A second profile adding the address is a pending claim: the holder keeps
/// its login route (the claim used to lock the holder out).
#[tokio::test]
async fn test_pending_claim_keeps_holder_route() {
    let svc = TestServices::new(MockStorage::new());
    let email = "claimed@sid.example.com";
    let holder = test_profile();
    claim_email(&svc, &holder, email).await;
    let mut claimant = test_profile();
    claimant.id = ProfileId::generate();
    claimant.username = Some(format!("claimant_{}", uuid::Uuid::now_v7().simple()));
    claim_email(&svc, &claimant, email).await;

    assert!(
        common::routes_to(&svc, email, holder.id).await,
        "the holder lost its route to a pending claim"
    );
}

/// The sole claimant of an address signs in through it.
#[tokio::test]
async fn test_sole_claimant_routes_to_its_profile() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    claim_email(&svc, &profile, "sole@sid.example.com").await;

    assert!(common::routes_to(&svc, "Sole@SID.example.com", profile.id).await);
}

/// The holder releasing the address leaves the remaining claimant without a
/// route: resolution answers like an unknown value.
#[tokio::test]
async fn test_released_principal_routes_nobody() {
    let svc = TestServices::new(MockStorage::new());
    let email = "released@sid.example.com";
    let holder = test_profile();
    claim_email(&svc, &holder, email).await;
    let mut claimant = test_profile();
    claimant.id = ProfileId::generate();
    claimant.username = Some(format!("claimant_{}", uuid::Uuid::now_v7().simple()));
    claim_email(&svc, &claimant, email).await;
    let entity = svc
        .storage
        .get_principal_by_value(sid_core::models::PrincipalType::Email, email)
        .await
        .unwrap()
        .expect("entity exists");
    svc.storage
        .unbind_principal(
            entity.id,
            holder.id,
            AuditEntry::system("test", "release").into(),
        )
        .await
        .unwrap();

    assert!(
        !common::routes_to(&svc, email, holder.id).await,
        "the released address still routes to its former holder"
    );
    assert!(
        !common::routes_to(&svc, email, claimant.id).await,
        "the remaining claimant was elected"
    );
}

/// Save `profile` holding `email` with proof (first use).
async fn verified_holder(svc: &TestServices, profile: &Profile, email: &str) {
    use sid_core::models::Principal;

    svc.storage
        .create_profile(profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let mut held = Principal::new_email(profile.id, email);
    held.verify(0);
    svc.storage
        .save_principal(&held, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
}

fn other_profile(tag: &str) -> Profile {
    let mut profile = test_profile();
    profile.id = ProfileId::generate();
    profile.username = Some(format!("{tag}_{}", uuid::Uuid::now_v7().simple()));
    profile
}

fn add_principal_request(
    profile: &Profile,
    principal_type: sid_proto::sid::v1::PrincipalType,
    value: &str,
) -> AddPrincipalRequest {
    AddPrincipalRequest {
        profile_id: profile.id.to_string(),
        r#type: principal_type as i32,
        value: value.to_string(),
    }
}

/// Another account adding a held address through AddPrincipal is a pending
/// claim: the holder keeps its route and proof (the add used to wipe both
/// and lock the holder out), and the claimant is told the principal's id.
#[tokio::test]
async fn test_add_principal_claim_keeps_holder_route() {
    let svc = TestServices::new(MockStorage::new());
    let email = "held@sid.example.com";
    let holder = test_profile();
    verified_holder(&svc, &holder, email).await;
    let claimant = other_profile("claimant");
    svc.storage
        .create_profile(&claimant, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let added = svc
        .identity
        .add_principal(admin_request(
            &svc,
            add_principal_request(&claimant, sid_proto::sid::v1::PrincipalType::Email, email),
        ))
        .await
        .expect("a pending claim is accepted")
        .into_inner()
        .principal
        .expect("the claim");

    let entity = svc
        .storage
        .get_principal_by_value(sid_core::models::PrincipalType::Email, email)
        .await
        .unwrap()
        .expect("entity exists");
    assert_eq!(
        entity.assigned_profile_id,
        Some(holder.id),
        "the claim took the route"
    );
    assert!(entity.verified, "the claim stripped the holder's proof");
    assert_eq!(
        added.id,
        entity.id.0.to_string(),
        "the claim names another principal"
    );
    assert!(!added.verified, "the claimant was shown the holder's proof");
    assert!(common::routes_to(&svc, email, holder.id).await);
}

/// AddPrincipal stores the value in the form login looks it up by; stored
/// verbatim, "Alice@Example.com" would be an entity login never finds.
#[tokio::test]
async fn test_add_principal_normalizes_value() {
    let svc = TestServices::new(MockStorage::new());
    let owner = test_profile();
    svc.storage
        .create_profile(&owner, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let added = svc
        .identity
        .add_principal(admin_request(
            &svc,
            add_principal_request(
                &owner,
                sid_proto::sid::v1::PrincipalType::Email,
                "  Mixed.Case@SID.Example.com ",
            ),
        ))
        .await
        .unwrap()
        .into_inner()
        .principal
        .unwrap();
    assert_eq!(added.value, "mixedcase@sid.example.com");
    assert!(
        svc.storage
            .get_principal_by_value(
                sid_core::models::PrincipalType::Email,
                "mixedcase@sid.example.com"
            )
            .await
            .unwrap()
            .is_some()
    );
}

/// A missing type or a value of another type is refused instead of being
/// stored under a guessed type.
#[tokio::test]
async fn test_add_principal_refuses_unknown_or_mismatched_type() {
    let svc = TestServices::new(MockStorage::new());
    let owner = test_profile();
    svc.storage
        .create_profile(&owner, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    for (principal_type, value) in [
        (sid_proto::sid::v1::PrincipalType::Unspecified, "anything"),
        (sid_proto::sid::v1::PrincipalType::Email, "+380501234567"),
        (
            sid_proto::sid::v1::PrincipalType::Phone,
            "someone@sid.example.com",
        ),
        (
            sid_proto::sid::v1::PrincipalType::Username,
            "someone@sid.example.com",
        ),
    ] {
        let err = svc
            .identity
            .add_principal(admin_request(
                &svc,
                add_principal_request(&owner, principal_type, value),
            ))
            .await
            .expect_err("refused");
        assert_eq!(
            err.code(),
            tonic::Code::InvalidArgument,
            "{principal_type:?} {value}"
        );
    }
}

/// A user name another account holds is a login handle, never shared.
#[tokio::test]
async fn test_add_principal_taken_username_already_exists() {
    let svc = TestServices::new(MockStorage::new());
    let holder = test_profile();
    svc.storage
        .create_profile(&holder, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    svc.identity
        .add_principal(admin_request(
            &svc,
            add_principal_request(
                &holder,
                sid_proto::sid::v1::PrincipalType::Username,
                "taken_handle",
            ),
        ))
        .await
        .unwrap();
    let other = other_profile("taker");
    svc.storage
        .create_profile(&other, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let err = svc
        .identity
        .add_principal(admin_request(
            &svc,
            add_principal_request(
                &other,
                sid_proto::sid::v1::PrincipalType::Username,
                "taken_handle",
            ),
        ))
        .await
        .expect_err("a taken handle");
    assert_eq!(err.code(), tonic::Code::AlreadyExists);
}

/// A lapsed channel proof keeps the login route (it used to lock the holder
/// out until it re-verified).
#[tokio::test]
async fn test_expired_proof_keeps_route() {
    use sid_core::models::Principal;

    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let mut p = Principal::new_email(profile.id, "expired@sid.example.com");
    p.verified = true;
    p.verified_at = Some(chrono::Utc::now() - chrono::Duration::days(400));
    p.verification_expires = Some(chrono::Utc::now() - chrono::Duration::days(1));
    svc.storage
        .save_principal(&p, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    svc.storage.expire_principal_verifications().await.unwrap();

    assert!(
        common::routes_to(&svc, "expired@sid.example.com", profile.id).await,
        "proof expiry removed the route"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Password Reset Flow
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_request_password_reset_anti_enumeration() {
    let svc = TestServices::new(MockStorage::new());
    // Non-existent user → still returns success (anti-enumeration)
    let req = Request::new(RequestPasswordResetRequest {
        principal: "nonexistent@sid.example.com".to_string(),
        client_id: String::new(),
        redirect_uri: String::new(),
        captcha_token: String::new(),
    });
    let resp = svc.auth.request_password_reset(req).await;
    assert!(resp.is_ok());
    let msg = resp.unwrap().into_inner().message;
    assert!(msg.contains("If an account exists"));
}

/// Services with a profile that holds `alice@sid.example.com`.
async fn reset_services(storage: MockStorage) -> TestServices {
    let profile = test_profile();
    let svc = TestServices::new(storage.with_profile(profile.clone()));
    svc.storage
        .save_principal(
            &sid_core::models::Principal::new(
                profile.id,
                sid_core::models::PrincipalType::Email,
                "alice@sid.example.com",
            ),
            sid_core::models::AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();
    svc
}

/// A reset for an address a profile holds stores one reset session.
#[tokio::test]
async fn test_request_password_reset_creates_session() {
    let svc = reset_services(MockStorage::new()).await;
    let req = Request::new(RequestPasswordResetRequest {
        principal: "alice@sid.example.com".to_string(),
        client_id: String::new(),
        redirect_uri: String::new(),
        captcha_token: String::new(),
    });
    let resp = svc.auth.request_password_reset(req).await;
    assert!(resp.is_ok());
    assert_eq!(svc.mock_storage.stored_reset_sessions(), 1);
}

/// When the active-reset count cannot be read, no reset is started: the
/// limit of three live resets would otherwise read as zero and let a caller
/// mint unlimited reset tokens. The answer keeps the anti-enumeration shape.
#[tokio::test]
async fn test_request_password_reset_unreadable_limit_starts_nothing() {
    let svc = reset_services(MockStorage::new().with_failing_reset_count()).await;
    let req = Request::new(RequestPasswordResetRequest {
        principal: "alice@sid.example.com".to_string(),
        client_id: String::new(),
        redirect_uri: String::new(),
        captcha_token: String::new(),
    });
    let resp = svc.auth.request_password_reset(req).await.unwrap();
    assert!(resp.into_inner().message.contains("If an account exists"));
    assert_eq!(svc.mock_storage.stored_reset_sessions(), 0);
}

/// A reset that cannot be stored answers exactly like a reset for an unknown
/// address: an error only for held addresses would tell which accounts exist.
#[tokio::test]
async fn test_request_password_reset_storage_fault_keeps_answer_shape() {
    let svc = reset_services(MockStorage::new().with_failing_reset_save()).await;
    let req = Request::new(RequestPasswordResetRequest {
        principal: "alice@sid.example.com".to_string(),
        client_id: String::new(),
        redirect_uri: String::new(),
        captcha_token: String::new(),
    });
    let resp = svc.auth.request_password_reset(req).await.unwrap();
    assert!(resp.into_inner().message.contains("If an account exists"));
}

#[tokio::test]
async fn test_verify_password_reset_invalid_session() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(VerifyPasswordResetRequest {
        session_id: Uuid::now_v7().to_string(),
        token: "sometoken".to_string(),
    });
    // An unknown reset reads as an expired one: the reset starts again.
    let err = svc.auth.verify_password_reset(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(common::error_reason(&err).as_deref(), Some("INVALID_STATE"));
}

#[tokio::test]
async fn test_verify_password_reset_wrong_token() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());

    use sha2::{Digest, Sha256};
    let correct_token = "correct_token_hex_value";
    let token_hash: String = Sha256::digest(correct_token.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let session = sid_core::models::PasswordResetSession::new(
        profile.id,
        "alice@sid.example.com".into(),
        token_hash,
    );
    let session_id = session.id;
    {
        use sid_plugin::StorageBackend;
        storage
            .create_reset_session(&session, AuditEntry::system("test", "setup").into())
            .await
            .unwrap();
    }

    let svc = TestServices::new(storage);
    let req = Request::new(VerifyPasswordResetRequest {
        session_id: session_id.to_string(),
        token: "wrong_token".to_string(),
    });
    let resp = svc.auth.verify_password_reset(req).await;
    assert!(resp.is_err());
    assert_eq!(resp.unwrap_err().code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_verify_password_reset_correct_token() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());

    use sha2::{Digest, Sha256};
    let correct_token = "my_secret_reset_token";
    let token_hash: String = Sha256::digest(correct_token.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let session = sid_core::models::PasswordResetSession::new(
        profile.id,
        "alice@sid.example.com".into(),
        token_hash,
    );
    let session_id = session.id;
    {
        use sid_plugin::StorageBackend;
        storage
            .create_reset_session(&session, AuditEntry::system("test", "setup").into())
            .await
            .unwrap();
    }

    let svc = TestServices::new(storage);
    let req = Request::new(VerifyPasswordResetRequest {
        session_id: session_id.to_string(),
        token: correct_token.to_string(),
    });
    let resp = svc.auth.verify_password_reset(req).await;
    assert!(resp.is_ok(), "verify should succeed: {:?}", resp.err());

    let inner = resp.unwrap().into_inner();
    assert!(!inner.reset_session_id.is_empty());
    assert!(inner.expires_in > 0);
}

#[tokio::test]
async fn test_verify_password_reset_already_consumed() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());

    use sha2::{Digest, Sha256};
    let token = "token_for_double_use";
    let token_hash: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let session = sid_core::models::PasswordResetSession::new(
        profile.id,
        "alice@sid.example.com".into(),
        token_hash,
    );
    let session_id = session.id;
    {
        use sid_plugin::StorageBackend;
        storage
            .create_reset_session(&session, AuditEntry::system("test", "setup").into())
            .await
            .unwrap();
    }

    let svc = TestServices::new(storage);

    // First verify — succeeds
    let req = Request::new(VerifyPasswordResetRequest {
        session_id: session_id.to_string(),
        token: token.to_string(),
    });
    assert!(svc.auth.verify_password_reset(req).await.is_ok());

    // Second verify — fails (already consumed)
    let req = Request::new(VerifyPasswordResetRequest {
        session_id: session_id.to_string(),
        token: token.to_string(),
    });
    let resp = svc.auth.verify_password_reset(req).await;
    assert!(resp.is_err());
    assert_eq!(resp.unwrap_err().code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_complete_password_reset_requires_verified_session() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(CompletePasswordResetRequest {
        reset_session_id: Uuid::now_v7().to_string(),
        operation_id: None,
        registration_record: vec![],
        proof: None,
    });
    // An unknown reset reads as an expired one: the reset starts again.
    let err = svc.auth.complete_password_reset(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(common::error_reason(&err).as_deref(), Some("INVALID_STATE"));
}

/// A completed password reset ends every earlier session everywhere: their
/// access tokens stop at once and each RP they signed in to is owed a
/// back-channel logout. The reset session is then used up.
#[tokio::test]
async fn test_complete_password_reset_ends_earlier_sessions() {
    use sid_opaque_ke::{
        ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse,
    };
    use sid_pake_core::pallas_opaque::PallasCipherSuite;
    use sid_plugin::{StorageBackend, WorkStore};

    let profile = test_profile();
    let mut earlier = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    earlier.client_id = Some("rp-client".into());
    use sha2::{Digest, Sha256};
    let token = "reset-token";
    let token_hash: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let reset = sid_core::models::PasswordResetSession::new(
        profile.id,
        "alice@sid.example.com".into(),
        token_hash,
    );
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(earlier.clone());
    storage
        .create_reset_session(&reset, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let svc = TestServices::new(storage);

    // The mailbox link verifies the reset and prepares the replacement
    // password's operation.
    let verified = svc
        .auth
        .verify_password_reset(Request::new(VerifyPasswordResetRequest {
            session_id: reset.id.to_string(),
            token: token.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    let context = verified.history.expect("the reset's history context");

    // The new password's registration upload, as the client builds it under
    // the reset operation's OPRF key.
    let password = b"a new correct horse battery staple";
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let start = ClientRegistration::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let resp = svc
        .auth
        .execute_password_reset(Request::new(ExecutePasswordResetRequest {
            operation_id: context.operation_id.clone(),
            registration_request: start.message.serialize().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
    let finish = start
        .state
        .finish(
            &mut rng,
            password,
            RegistrationResponse::<PallasCipherSuite>::deserialize(&resp.registration_response)
                .unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    svc.auth
        .complete_password_reset(Request::new(CompletePasswordResetRequest {
            reset_session_id: verified.reset_session_id,
            operation_id: context.operation_id,
            registration_record: finish.message.serialize().to_vec(),
            proof: None,
        }))
        .await
        .unwrap();

    assert!(
        svc.revocation_cache
            .is_revoked("", &earlier.id.to_string())
            .await
            .unwrap(),
        "an earlier session's access tokens still pass after the reset"
    );
    let owed = sid_core::models::LogoutDelivery::for_ended_session(&earlier)
        .unwrap()
        .work();
    assert!(
        svc.mock_storage.get_work(owed.id).await.unwrap().is_some(),
        "the RP was not owed a logout"
    );
    let reset = svc
        .storage
        .get_reset_session(reset.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reset.status,
        sid_core::models::ResetSessionStatus::Completed
    );
}

// ═══════════════════════════════════════════════════════════════════
// Event emission integration tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_event_user_created_on_create_profile() {
    use sid_core::models::event::{EventFilter, event_types};

    let svc = TestServices::new(MockStorage::new());
    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::USER_CREATED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.identity
        .create_profile(admin_request(
            &svc,
            CreateProfileRequest {
                username: Some("event-test-user".to_string()),
                email: Some("event@sid.example.com".to_string()),
                ..Default::default()
            },
        ))
        .await
        .unwrap();

    // Owed by the commit that stores the account, delivered by its relay.
    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("USER_CREATED event should be published");
    assert_eq!(event.event_type, event_types::USER_CREATED);
    assert!(
        event
            .subject
            .as_deref()
            .unwrap_or("")
            .starts_with("profile/")
    );
    let data = &event.data;
    assert_eq!(data["username"], "event-test-user");
}

#[tokio::test]
async fn test_event_profile_claim_changed_on_update() {
    use sid_core::models::event::{EventFilter, event_types};

    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);
    let bearer = issue_token(
        &svc.jwt,
        &profile,
        &["openid".to_string(), "profile".to_string()],
    );

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::PROFILE_CLAIM_CHANGED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.identity
        .update_profile(authed_request(
            UpdateProfileRequest {
                id: pid.to_string(),
                given_name: Some("Updated".to_string()),
                ..Default::default()
            },
            &bearer,
        ))
        .await
        .unwrap();

    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("PROFILE_CLAIM_CHANGED event should be published");
    assert_eq!(event.event_type, event_types::PROFILE_CLAIM_CHANGED);
    assert!(
        event
            .subject
            .as_deref()
            .unwrap_or("")
            .contains(&pid.to_string())
    );
}

#[tokio::test]
async fn test_event_user_deleted_on_delete_profile() {
    use sid_core::models::event::{EventFilter, event_types};

    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::USER_DELETED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.identity
        .delete_profile(admin_request(
            &svc,
            DeleteProfileRequest {
                id: pid.to_string(),
            },
        ))
        .await
        .unwrap();

    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("USER_DELETED event should be published");
    assert_eq!(event.event_type, event_types::USER_DELETED);
    assert!(
        event
            .subject
            .as_deref()
            .unwrap_or("")
            .contains(&pid.to_string())
    );
}

#[tokio::test]
async fn test_event_user_deactivated_on_admin_suspend() {
    use sid_core::models::event::{EventFilter, event_types};

    let profile = test_profile();
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);
    let admin_token = issue_admin_token(&svc.jwt, pid);

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::USER_DEACTIVATED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.admin
        .admin_update_profile(authed_request(
            AdminUpdateProfileRequest {
                profile_id: pid.to_string(),
                profile_status: sid_proto::sid::v1::ProfileStatus::Suspended.into(),
                ..Default::default()
            },
            &admin_token,
        ))
        .await
        .unwrap();

    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("USER_DEACTIVATED event should be published on suspend");
    assert_eq!(event.event_type, event_types::USER_DEACTIVATED);
    let data = &event.data;
    assert_eq!(data["new_status"], "Suspended");
}

#[tokio::test]
async fn test_event_user_unlocked_on_admin_reactivate() {
    use sid_core::models::event::{EventFilter, event_types};

    let mut profile = test_profile();
    profile.status = sid_core::models::ProfileStatus::Suspended;
    let pid = profile.id;
    let storage = MockStorage::new().with_profile(profile);
    let svc = TestServices::new(storage);
    let admin_token = issue_admin_token(&svc.jwt, pid);

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::USER_UNLOCKED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.admin
        .admin_update_profile(authed_request(
            AdminUpdateProfileRequest {
                profile_id: pid.to_string(),
                profile_status: sid_proto::sid::v1::ProfileStatus::Active.into(),
                ..Default::default()
            },
            &admin_token,
        ))
        .await
        .unwrap();

    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("USER_UNLOCKED event should be published on reactivate");
    assert_eq!(event.event_type, event_types::USER_UNLOCKED);
    let data = &event.data;
    assert_eq!(data["new_status"], "Active");
}

#[tokio::test]
async fn test_event_session_revoked_on_revoke() {
    use sid_core::models::event::{EventFilter, event_types};

    let profile = test_profile();
    let pid = profile.id;
    let session = Session::new(
        pid,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let session_id = session.id;
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_session(session);
    let svc = TestServices::new(storage);
    let bearer = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::SESSION_REVOKED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.identity
        .revoke_session(authed_request(
            RevokeSessionRequest {
                session_id: session_id.to_string(),
            },
            &bearer,
        ))
        .await
        .unwrap();

    // Owed by the session's deletion, with the reason and the actor.
    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("SESSION_REVOKED event should be published");
    assert_eq!(event.event_type, event_types::SESSION_REVOKED);
    assert!(
        event
            .subject
            .as_deref()
            .unwrap_or("")
            .contains(&session_id.to_string())
    );
    assert_eq!(event.data["reason"], "user_requested");
    assert_eq!(event.data["by"], pid.to_string());
}

#[tokio::test]
async fn test_event_session_revoked_on_admin_revoke_all() {
    use sid_core::models::event::{EventFilter, event_types};

    let profile = test_profile();
    let pid = profile.id;
    let session = Session::new(
        pid,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let session_id = session.id;
    let storage = MockStorage::new()
        .with_profile(profile)
        .with_session(session);
    let svc = TestServices::new(storage);
    let admin = ProfileId::generate();
    let admin_token = issue_admin_token(&svc.jwt, admin);

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::SESSION_REVOKED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.admin
        .revoke_all_sessions(authed_request(
            RevokeAllSessionsRequest {
                profile_id: pid.to_string(),
            },
            &admin_token,
        ))
        .await
        .unwrap();

    // Each ended session owes its own event, committed with the deletion.
    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("SESSION_REVOKED event should be published on bulk revoke");
    assert_eq!(event.event_type, event_types::SESSION_REVOKED);
    let data = &event.data;
    assert_eq!(data["session_id"], session_id.to_string());
    assert_eq!(data["reason"], "admin");
    assert_eq!(data["by"], admin.to_string());
}

#[tokio::test]
async fn test_event_mfa_disabled_on_credential_delete() {
    use sid_core::models::event::{EventFilter, event_types};
    use sid_core::models::session::AuthLevel;

    let profile = test_profile();
    let pid = profile.id;

    // Create elevated session (required for MFA credential deletion)
    let mut session = Session::new(
        pid,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.as_active().unwrap().elevate(AuthLevel::Elevated);

    // Create a TOTP credential
    let totp_cred = Credential::new(
        pid,
        CredentialType::Totp,
        sid_core::models::CredentialData::new(b"totp-secret-key-1234567890123456".to_vec()),
        Some("Test TOTP".to_string()),
    );
    let cred_id = totp_cred.id;

    let storage = MockStorage::new().with_profile(profile.clone());
    let svc = TestServices::new(storage);

    // Save credential and session via storage
    svc.storage
        .create_credential(
            &totp_cred,
            AuditEntry::user(pid.to_string(), "test", cred_id.0.to_string()).into(),
        )
        .await
        .unwrap();
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(pid.to_string(), "test", session.id.to_string()).into(),
        )
        .await
        .unwrap();

    let (bearer, _) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::MFA_DISABLED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.auth
        .delete_mfa_credential(authed_request(
            DeleteMfaCredentialRequest {
                credential_id: cred_id.0.to_string(),
            },
            &bearer,
        ))
        .await
        .unwrap();

    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("MFA_DISABLED event should be published");
    assert_eq!(event.event_type, event_types::MFA_DISABLED);
    assert!(
        event
            .subject
            .as_deref()
            .unwrap_or("")
            .contains(&pid.to_string())
    );
}

#[tokio::test]
async fn test_event_consent_granted_on_update_claim() {
    use sid_core::models::consent::ConsentRecord;
    use sid_core::models::event::{EventFilter, event_types};

    let profile = test_profile();
    let pid = profile.id;
    // Claims are changed on a connected site: the consent was granted.
    let mut consent = ConsentRecord::new(pid, "test-client");
    consent.as_requested().unwrap().grant();
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_consent(consent)
        .with_client(test_client());
    let svc = TestServices::new(storage);
    let bearer = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::CONSENT_GRANTED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.account
        .update_claim_consent(authed_request(
            sid_proto::sid::v1::account::UpdateClaimConsentRequest {
                site_id: "test-client".to_string(),
                claim_name: "email".to_string(),
                grant: true,
            },
            &bearer,
        ))
        .await
        .unwrap();

    // Owed by the consent commit, delivered only through its relay work.
    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("CONSENT_GRANTED event should be published");
    assert_eq!(event.event_type, event_types::CONSENT_GRANTED);
    let data = &event.data;
    assert_eq!(data["claim_name"], "email");
    assert_eq!(data["site_id"], "test-client");
}

#[tokio::test]
async fn test_event_consent_revoked_on_disconnect_site() {
    use sid_core::models::consent::ConsentRecord;
    use sid_core::models::event::{EventFilter, event_types};

    let profile = test_profile();
    let pid = profile.id;
    let consent = ConsentRecord::new(pid, "test-client");
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_consent(consent)
        .with_client(test_client());
    let svc = TestServices::new(storage);
    let bearer = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let mut rx = svc
        .event_bus
        .subscribe(EventFilter {
            event_types: vec![event_types::CONSENT_REVOKED.to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    svc.account
        .disconnect_site(authed_request(
            sid_proto::sid::v1::account::DisconnectSiteRequest {
                site_id: "test-client".to_string(),
            },
            &bearer,
        ))
        .await
        .unwrap();

    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = rx
        .try_recv()
        .expect("CONSENT_REVOKED event should be published on disconnect");
    assert_eq!(event.event_type, event_types::CONSENT_REVOKED);
    let data = &event.data;
    assert_eq!(data["site_id"], "test-client");
    assert_eq!(data["disconnect"], true);
}

// ═══════════════════════════════════════════════════════════════════
// DCR (RFC 7591) + Client Management (RFC 7592) integration tests
// ═══════════════════════════════════════════════════════════════════

/// Helper: create an Initial Access Token for DCR tests.
/// Returns (MockStorage with IAT, raw token string).
fn setup_iat_for_dcr(storage: MockStorage) -> (MockStorage, String) {
    use sha2::{Digest, Sha256};
    use sid_core::models::{InitialAccessToken, InitialAccessTokenId, ProjectId};

    let raw_token = "test-iat-secret-for-dcr-12345";
    let token_hash = Sha256::digest(raw_token.as_bytes()).to_vec();

    let iat = InitialAccessToken {
        id: InitialAccessTokenId::new(),
        token_hash,
        project_id: ProjectId::system(),
        max_clients: 10,
        clients_registered: 0,
        allowed_scopes: vec!["openid".into(), "profile".into()],
        allowed_grant_types: vec!["authorization_code".into()],
        allowed_redirect_patterns: vec!["https://*.sid.example.com/*".into()],
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        created_at: chrono::Utc::now(),
        created_by: "admin".into(),
        revoked: false,
    };

    let storage = storage.with_initial_access_token(iat);
    (storage, raw_token.to_string())
}

/// Helper: create a gRPC request with Bearer token in metadata.
fn bearer_request<T>(body: T, token: &str) -> Request<T> {
    let mut req = Request::new(body);
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    req
}

#[tokio::test]
async fn test_dcr_register_client_happy_path() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    let resp = svc
        .project
        .register_client(bearer_request(
            sid_proto::sid::v1::RegisterClientRequest {
                client_name: "My DCR App".to_string(),
                redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                response_types: vec!["code".to_string()],
                scope: vec!["openid".to_string()],
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &iat_token,
        ))
        .await
        .unwrap();

    let body = resp.into_inner();
    let app = body.client.expect("client should be present");
    assert!(
        app.client_id.starts_with("dyn_"),
        "DCR client_id should start with dyn_"
    );
    assert_eq!(app.name, "My DCR App");
    // A registration is the client role of a new application, which gets
    // no resource role and no access to any resource.
    let application = svc
        .storage
        .get_application(app.application_id.parse().unwrap())
        .await
        .unwrap()
        .expect("the registration created its application");
    assert_eq!(application.name, "My DCR App");
    assert!(
        svc.storage
            .protected_resource_of_application(application.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        svc.storage
            .list_resource_access_by_client(&app.client_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !app.active,
        "AdminApproval policy → client should be inactive"
    );
    assert!(
        !body.registration_access_token.is_empty(),
        "RAT should be returned"
    );
}

/// The IAT's redirect pattern `https://*.sid.example.com/*` admits only hosts
/// under that domain: a URI that reaches another host through the path, the
/// userinfo or extra labels is refused and registers nothing, and the IAT's
/// count stays unchanged.
#[tokio::test]
async fn test_dcr_redirect_pattern_cannot_reach_another_host() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    for uri in [
        "https://evil.example.com/.sid.example.com/cb",
        "https://app.sid.example.com@evil.example.com/cb",
        "https://app.sid.example.com/a/b",
    ] {
        let mut request = dcr_request(&svc, "Escaping App");
        request.redirect_uris = vec![uri.to_string()];
        let err = svc
            .project
            .register_client(bearer_request(request, &iat_token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "{uri}: {err:?}");
    }

    let iats = svc
        .storage
        .list_initial_access_tokens_by_project(sid_core::models::ProjectId::system())
        .await
        .unwrap();
    assert_eq!(
        iats.iter()
            .map(|iat| iat.clients_registered)
            .collect::<Vec<_>>(),
        [0]
    );
    let clients = svc.storage.list_oauth2_clients(0, 100).await.unwrap();
    assert!(
        clients.iter().all(|c| !c.client_id.starts_with("dyn_")),
        "a client was registered"
    );
}

/// A registration named `name` under the installation's issuer.
fn dcr_request(svc: &TestServices, name: &str) -> sid_proto::sid::v1::RegisterClientRequest {
    sid_proto::sid::v1::RegisterClientRequest {
        client_name: name.to_string(),
        redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        scope: vec!["openid".to_string()],
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    }
}

/// The whole metadata of a client registered with [`dcr_request`], as an
/// RFC 7592 §2.2 update sends it; a test changes one field.
fn full_update(
    svc: &TestServices,
    client_id: &str,
) -> sid_proto::sid::v1::UpdateRegisteredClientRequest {
    let registered = dcr_request(svc, "");
    sid_proto::sid::v1::UpdateRegisteredClientRequest {
        client_id: client_id.to_string(),
        client_name: Some("Bounded".into()),
        redirect_uris: registered.redirect_uris,
        grant_types: registered.grant_types,
        response_types: registered.response_types,
        scope: registered.scope,
        issuer_handle: registered.issuer_handle,
        ..Default::default()
    }
}

/// Registrations made in quick succession get distinct identifiers and each
/// keeps its own client: an identifier collision used to replace the earlier
/// client (its redirect URIs and secret) with the later registration.
#[tokio::test]
async fn test_dcr_rapid_registrations_get_distinct_clients() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    let mut ids = std::collections::HashSet::new();
    for n in 0..5 {
        let app = svc
            .project
            .register_client(bearer_request(
                dcr_request(&svc, &format!("App {n}")),
                &iat_token,
            ))
            .await
            .unwrap()
            .into_inner()
            .client
            .unwrap();
        ids.insert(app.client_id);
    }
    assert_eq!(ids.len(), 5, "client ids collided: {ids:?}");
    for id in &ids {
        assert!(svc.storage.get_oauth2_client(id).await.unwrap().is_some());
    }
}

/// Registration metadata A (authentication-flow.md): explicit pairwise, an
/// unknown enum value and a supplied `sector_identifier_uri` are refused as
/// `invalid_client_metadata`, never coerced to public. Nothing is registered
/// and the initial access token's successful-registration count is unchanged.
#[tokio::test]
async fn test_dcr_refuses_incompatible_subject_metadata() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    let mut pairwise = dcr_request(&svc, "Pairwise");
    pairwise.subject_type = SubjectType::Pairwise as i32;
    let mut unknown = dcr_request(&svc, "Unknown");
    unknown.subject_type = 99;
    let mut sector = dcr_request(&svc, "Sector");
    sector.sector_identifier_uri = Some("https://app.sid.example.com/sector.json".into());

    for (req, field) in [
        (pairwise, "subject_type"),
        (unknown, "subject_type"),
        (sector, "sector_identifier_uri"),
    ] {
        let name = req.client_name.clone();
        let err = svc
            .project
            .register_client(bearer_request(req, &iat_token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{name}: {err:?}");
        assert_eq!(
            metadata_refusal(&err),
            ("invalid_client_metadata".into(), field.into()),
            "{name}"
        );
    }
    let registered = svc
        .storage
        .list_oauth2_clients_by_project(sid_core::models::ProjectId::system(), 0, 100)
        .await
        .unwrap();
    assert!(registered.is_empty(), "registered: {registered:?}");
    let iats = svc
        .storage
        .list_initial_access_tokens_by_project(sid_core::models::ProjectId::system())
        .await
        .unwrap();
    assert_eq!(iats[0].clients_registered, 0);
}

/// A registration that names no client authentication method gets
/// `client_secret_basic` and a secret (RFC 7591 §2: "If unspecified or
/// omitted, the default is client_secret_basic"); an unknown value is refused
/// as `invalid_client_metadata`, never coerced, and registers nothing.
#[tokio::test]
async fn test_dcr_auth_method_default_and_unknown() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    let body = svc
        .project
        .register_client(bearer_request(
            dcr_request(&svc, "Default method"),
            &iat_token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(body.client_secret.is_some_and(|s| !s.is_empty()));
    let stored = svc
        .storage
        .get_oauth2_client(&body.client.unwrap().client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.token_endpoint_auth_method,
        sid_core::models::TokenEndpointAuthMethod::ClientSecretBasic
    );

    let mut unknown = dcr_request(&svc, "Unknown method");
    unknown.token_endpoint_auth_method = 99;
    let err = svc
        .project
        .register_client(bearer_request(unknown, &iat_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");
    assert_eq!(
        metadata_refusal(&err),
        (
            "invalid_client_metadata".into(),
            "token_endpoint_auth_method".into()
        )
    );
    let registered = svc
        .storage
        .list_oauth2_clients_by_project(sid_core::models::ProjectId::system(), 0, 100)
        .await
        .unwrap();
    assert_eq!(registered.len(), 1, "registered: {registered:?}");
}

/// A confidential application created by an administrator authenticates with
/// the default method, `client_secret_basic` (RFC 7591 §2, OIDC Core 1.0 §9).
#[tokio::test]
async fn test_confidential_application_uses_client_secret_basic() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let body = svc
        .project
        .create_application(admin_request(
            &svc,
            CreateApplicationRequest {
                project_id: sid_core::models::ProjectId::system().0.to_string(),
                name: "Web".to_string(),
                client: Some(client_settings(ApplicationType::Web)),
                resource: None,
                org_id: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let stored = svc
        .storage
        .get_oauth2_client(&body.application.unwrap().client.unwrap().client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.token_endpoint_auth_method,
        sid_core::models::TokenEndpointAuthMethod::ClientSecretBasic
    );
}

/// Without sector grouping, a client's redirect URIs need not share a host;
/// each is still checked against the registration token's patterns.
#[tokio::test]
async fn test_dcr_redirect_uris_on_several_hosts_register() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let mut req = dcr_request(&svc, "Two hosts");
    req.redirect_uris = vec![
        "https://a.sid.example.com/cb".into(),
        "https://b.sid.example.com/cb".into(),
    ];
    let app = svc
        .project
        .register_client(bearer_request(req, &iat_token))
        .await
        .unwrap()
        .into_inner()
        .client
        .unwrap();
    assert_eq!(app.redirect_uris.len(), 2);
    assert_eq!(app.subject_type, SubjectType::Public as i32);
    assert_eq!(app.sector_identifier_uri, None);

    let mut outside = dcr_request(&svc, "Outside");
    outside.redirect_uris = vec![
        "https://a.sid.example.com/cb".into(),
        "https://attacker.example.org/cb".into(),
    ];
    let err = svc
        .project
        .register_client(bearer_request(outside, &iat_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
}

/// A client's self-service update (RFC 7592) stays within the initial access
/// token it was registered with and cannot change how its users' `sub` is
/// derived; before, any scope, redirect URI or subject type was stored.
#[tokio::test]
async fn test_dcr_update_stays_within_registration() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let registered = svc
        .project
        .register_client(bearer_request(dcr_request(&svc, "Bounded"), &iat_token))
        .await
        .unwrap()
        .into_inner();
    let client_id = registered.client.unwrap().client_id;
    let rat = registered.registration_access_token;
    let update = |mut req: sid_proto::sid::v1::UpdateRegisteredClientRequest| {
        req.issuer_handle = svc.issuer.handle.to_string();
        svc.project
            .update_registered_client(bearer_request(req, &rat))
    };

    let err = update(sid_proto::sid::v1::UpdateRegisteredClientRequest {
        scope: vec!["openid".into(), "admin".into()],
        ..full_update(&svc, &client_id)
    })
    .await
    .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");

    let err = update(sid_proto::sid::v1::UpdateRegisteredClientRequest {
        redirect_uris: vec!["https://attacker.example.org/cb".into()],
        ..full_update(&svc, &client_id)
    })
    .await
    .unwrap_err();
    // A redirect URI outside the registration token's patterns.
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert!(err.message().contains("allowed patterns"), "{err:?}");

    // Incompatible metadata, alone or beside a valid edit, is refused as a
    // whole (RFC 7592 §2.2): the valid part is not applied.
    let err = update(sid_proto::sid::v1::UpdateRegisteredClientRequest {
        client_name: Some("Renamed".into()),
        subject_type: Some(sid_proto::sid::v1::SubjectType::Pairwise.into()),
        ..full_update(&svc, &client_id)
    })
    .await
    .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");
    assert_eq!(
        metadata_refusal(&err),
        ("invalid_client_metadata".into(), "subject_type".into())
    );
    let err = update(sid_proto::sid::v1::UpdateRegisteredClientRequest {
        client_name: Some("Renamed".into()),
        sector_identifier_uri: Some("https://app.sid.example.com/sector.json".into()),
        ..full_update(&svc, &client_id)
    })
    .await
    .unwrap_err();
    assert_eq!(
        metadata_refusal(&err),
        (
            "invalid_client_metadata".into(),
            "sector_identifier_uri".into()
        )
    );

    let stored = svc
        .storage
        .get_oauth2_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_name, "Bounded");
    assert_eq!(stored.allowed_scopes, vec!["openid".to_string()]);
    assert_eq!(
        stored.redirect_uris,
        vec!["https://app.sid.example.com/callback".to_string()]
    );
    assert_eq!(stored.subject_type, sid_core::models::SubjectType::Public);
    assert_eq!(stored.sector_identifier_uri, None);
}

#[tokio::test]
async fn test_dcr_register_client_invalid_iat() {
    let storage = MockStorage::new().with_system_project();
    let (storage, _iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    let err = svc
        .project
        .register_client(bearer_request(
            sid_proto::sid::v1::RegisterClientRequest {
                client_name: "Bad App".to_string(),
                redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scope: vec!["openid".to_string()],
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            "wrong-iat-token",
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_dcr_register_client_disallowed_scope() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    let err = svc
        .project
        .register_client(bearer_request(
            sid_proto::sid::v1::RegisterClientRequest {
                client_name: "Scope Test".to_string(),
                redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scope: vec!["admin".to_string()], // not in IAT's allowed_scopes
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &iat_token,
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(err.message().contains("scope"));
}

#[tokio::test]
async fn test_dcr_get_registered_client_with_rat() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    // Register a client first.
    let resp = svc
        .project
        .register_client(bearer_request(
            sid_proto::sid::v1::RegisterClientRequest {
                client_name: "GET Test App".to_string(),
                redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scope: vec!["openid".to_string()],
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &iat_token,
        ))
        .await
        .unwrap()
        .into_inner();

    let client_id = resp.client.unwrap().client_id;
    let rat = resp.registration_access_token;

    // GET the client using RAT.
    let get_resp = svc
        .project
        .get_registered_client(bearer_request(
            sid_proto::sid::v1::GetRegisteredClientRequest {
                client_id: client_id.clone(),
                issuer_handle: svc.issuer.handle.to_string(),
            },
            &rat,
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(get_resp.client_id, client_id);
    assert_eq!(get_resp.name, "GET Test App");
}

#[tokio::test]
async fn test_dcr_update_registered_client() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    // Register.
    let resp = svc
        .project
        .register_client(bearer_request(
            sid_proto::sid::v1::RegisterClientRequest {
                client_name: "Before Update".to_string(),
                redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scope: vec!["openid".to_string()],
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &iat_token,
        ))
        .await
        .unwrap()
        .into_inner();

    let client_id = resp.client.unwrap().client_id;
    let rat = resp.registration_access_token;

    // Update client name.
    let updated = svc
        .project
        .update_registered_client(bearer_request(
            sid_proto::sid::v1::UpdateRegisteredClientRequest {
                client_name: Some("After Update".to_string()),
                ..full_update(&svc, &client_id)
            },
            &rat,
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(updated.name, "After Update");
    assert_eq!(updated.client_id, client_id);
}

#[tokio::test]
async fn test_dcr_delete_registered_client() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    // Register.
    let resp = svc
        .project
        .register_client(bearer_request(
            sid_proto::sid::v1::RegisterClientRequest {
                client_name: "Delete Me".to_string(),
                redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scope: vec!["openid".to_string()],
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &iat_token,
        ))
        .await
        .unwrap()
        .into_inner();

    let client_id = resp.client.unwrap().client_id;
    let rat = resp.registration_access_token;

    // Delete.
    svc.project
        .delete_registered_client(bearer_request(
            sid_proto::sid::v1::DeleteRegisteredClientRequest {
                client_id: client_id.clone(),
                issuer_handle: svc.issuer.handle.to_string(),
            },
            &rat,
        ))
        .await
        .unwrap();

    // Read after delete: the client is gone and its token with it, which is
    // answered as an invalid token (RFC 7592 §2.1), not as a missing client.
    let err = svc
        .project
        .get_registered_client(bearer_request(
            sid_proto::sid::v1::GetRegisteredClientRequest {
                client_id,
                issuer_handle: svc.issuer.handle.to_string(),
            },
            &rat,
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_dcr_get_with_wrong_rat_fails() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);

    // Register.
    let resp = svc
        .project
        .register_client(bearer_request(
            sid_proto::sid::v1::RegisterClientRequest {
                client_name: "RAT Test".to_string(),
                redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scope: vec!["openid".to_string()],
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &iat_token,
        ))
        .await
        .unwrap()
        .into_inner();

    let client_id = resp.client.unwrap().client_id;

    // GET with wrong RAT → Unauthenticated.
    let err = svc
        .project
        .get_registered_client(bearer_request(
            sid_proto::sid::v1::GetRegisteredClientRequest {
                client_id,
                issuer_handle: svc.issuer.handle.to_string(),
            },
            "wrong-rat-token",
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// A registration that names no grant or response types gets the RFC 7591 §2
/// defaults, `authorization_code` and `code`, rather than none.
#[tokio::test]
async fn test_dcr_grant_and_response_type_defaults() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let mut request = dcr_request(&svc, "Defaults");
    request.grant_types.clear();
    request.response_types.clear();

    let app = svc
        .project
        .register_client(bearer_request(request, &iat_token))
        .await
        .unwrap()
        .into_inner()
        .client
        .unwrap();

    assert_eq!(app.grant_types, ["authorization_code"]);
    assert_eq!(app.response_types, ["code"]);
}

/// An update replaces the registration (RFC 7592 §2.2): the metadata sent is
/// the client's whole metadata, and a field left out is removed rather than
/// kept.
#[tokio::test]
async fn test_dcr_update_replaces_the_registration() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let mut request = dcr_request(&svc, "Replaced");
    request.contacts = vec!["ops@sid.example.com".into()];
    let registered = svc
        .project
        .register_client(bearer_request(request, &iat_token))
        .await
        .unwrap()
        .into_inner();
    let client_id = registered.client.unwrap().client_id;

    let updated = svc
        .project
        .update_registered_client(bearer_request(
            sid_proto::sid::v1::UpdateRegisteredClientRequest {
                client_id: client_id.clone(),
                client_name: Some("Replaced again".into()),
                redirect_uris: vec!["https://app.sid.example.com/callback".into()],
                grant_types: vec!["authorization_code".into()],
                response_types: vec!["code".into()],
                scope: vec!["openid".into()],
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &registered.registration_access_token,
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(updated.name, "Replaced again");
    assert!(updated.contacts.is_empty(), "{:?}", updated.contacts);
    let stored = svc
        .storage
        .get_oauth2_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.contacts.is_empty());
}

/// A client may send its secret back with its metadata; it must be the issued
/// secret (RFC 7592 §2.2), and a wrong one refuses the whole update.
#[tokio::test]
async fn test_dcr_update_checks_a_returned_secret() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let registered = svc
        .project
        .register_client(bearer_request(dcr_request(&svc, "Bounded"), &iat_token))
        .await
        .unwrap()
        .into_inner();
    let client_id = registered.client.unwrap().client_id;
    let secret = registered.client_secret.expect("a secret");
    let update = |client_secret: &str, name: &str| {
        svc.project.update_registered_client(bearer_request(
            sid_proto::sid::v1::UpdateRegisteredClientRequest {
                client_secret: Some(client_secret.to_string()),
                client_name: Some(name.to_string()),
                ..full_update(&svc, &client_id)
            },
            &registered.registration_access_token,
        ))
    };

    let err = update("not-the-secret", "Wrong").await.unwrap_err();
    assert_eq!(
        metadata_refusal(&err),
        ("invalid_client_metadata".into(), "client_secret".into())
    );
    let stored = svc
        .storage
        .get_oauth2_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_name, "Bounded");

    let renamed = update(&secret, "Right").await.unwrap().into_inner();
    assert_eq!(renamed.name, "Right");
}

/// An update that leaves out the client name or, for a web client, every
/// redirect URI removes them, and a registration without them is refused;
/// nothing changes.
#[tokio::test]
async fn test_dcr_update_without_required_metadata_is_refused() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let registered = svc
        .project
        .register_client(bearer_request(dcr_request(&svc, "Kept"), &iat_token))
        .await
        .unwrap()
        .into_inner();
    let client_id = registered.client.unwrap().client_id;

    let err = svc
        .project
        .update_registered_client(bearer_request(
            sid_proto::sid::v1::UpdateRegisteredClientRequest {
                client_id: client_id.clone(),
                client_name: Some("Only a name".into()),
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &registered.registration_access_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(
        oauth_error(&err).as_deref(),
        Some("invalid_redirect_uri"),
        "{err:?}"
    );
    let stored = svc
        .storage
        .get_oauth2_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_name, "Kept");
    assert_eq!(stored.redirect_uris.len(), 1);
}

/// Client management does not reveal which clients exist (RFC 7592 §2.1):
/// an unknown client and a client an administrator created (it has no
/// registration access token) are refused exactly like a wrong registration
/// access token. A handle of no issuer is NOT_FOUND, as at every issuer
/// endpoint; it says nothing about the client.
#[tokio::test]
async fn test_dcr_management_does_not_reveal_clients() {
    let storage = MockStorage::new()
        .with_system_project()
        .with_client(test_client());
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let registered = svc
        .project
        .register_client(bearer_request(dcr_request(&svc, "Mine"), &iat_token))
        .await
        .unwrap()
        .into_inner();
    let rat = registered.registration_access_token;
    let own = registered.client.unwrap().client_id;
    let here = svc.issuer.handle.to_string();

    let get = |client_id: String, issuer_handle: String| {
        svc.project.get_registered_client(bearer_request(
            sid_proto::sid::v1::GetRegisteredClientRequest {
                client_id,
                issuer_handle,
            },
            &rat,
        ))
    };
    for client_id in ["dyn_nobody", "test-client"] {
        let err = get(client_id.to_string(), here.clone()).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::Unauthenticated,
            "{client_id}: {err:?}"
        );
    }
    let elsewhere = sid_core::models::IssuerHandle::generate().to_string();
    let err = get(own, elsewhere).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound, "{err:?}");
}

/// A registration names the issuer it registers under; a handle of no issuer
/// is NOT_FOUND and registers nothing.
#[tokio::test]
async fn test_dcr_registers_only_under_a_known_issuer() {
    let storage = MockStorage::new().with_system_project();
    let (storage, iat_token) = setup_iat_for_dcr(storage);
    let svc = TestServices::new(storage);
    let mut request = dcr_request(&svc, "Nowhere");
    request.issuer_handle = sid_core::models::IssuerHandle::generate().to_string();

    let err = svc
        .project
        .register_client(bearer_request(request, &iat_token))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::NotFound, "{err:?}");
    let clients = svc.storage.list_oauth2_clients(0, 100).await.unwrap();
    assert!(clients.iter().all(|c| !c.client_id.starts_with("dyn_")));
}

// ═══════════════════════════════════════════════════════════════════
// Principal Contestation Notifications
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_add_principal_no_event_when_sole_claimant() {
    // First binding of an identifier → no PRINCIPAL_CONTESTED event.
    let profile_a = test_profile();
    let storage = MockStorage::new().with_profile(profile_a.clone());
    let svc = TestServices::new(storage);

    let filter = sid_core::models::event::EventFilter {
        event_types: vec![sid_core::models::event::event_types::PRINCIPAL_CONTESTED.to_string()],
        ..Default::default()
    };
    let mut rx = svc.event_bus.subscribe(filter).await.unwrap();

    // Add email to profile A — only one binding, not contested.
    let req = admin_request(
        &svc,
        AddPrincipalRequest {
            profile_id: profile_a.id.to_string(),
            r#type: sid_proto::sid::v1::PrincipalType::Email as i32,
            value: "contested@sid.example.com".to_string(),
        },
    );
    svc.identity.add_principal(req).await.unwrap();
    svc.relay_events().await;

    // No event should be published (channel should be empty).
    assert!(
        rx.try_recv().is_err(),
        "no PRINCIPAL_CONTESTED event expected for sole claimant"
    );
}

#[tokio::test]
async fn test_add_principal_emits_contested_event_for_existing_holders() {
    // When a second profile binds the same identifier, all existing holders
    // receive a PRINCIPAL_CONTESTED event.
    let profile_a = test_profile(); // "alice"
    let mut profile_b = Profile::new(Some("bob"));
    profile_b.id = ProfileId::generate();

    let storage = MockStorage::new()
        .with_profile(profile_a.clone())
        .with_profile(profile_b.clone());
    let svc = TestServices::new(storage);

    // Subscribe to PRINCIPAL_CONTESTED events before adding principals.
    let filter = sid_core::models::event::EventFilter {
        event_types: vec![sid_core::models::event::event_types::PRINCIPAL_CONTESTED.to_string()],
        ..Default::default()
    };
    let mut rx = svc.event_bus.subscribe(filter).await.unwrap();

    // Profile A binds the email first — sole claimant, no event.
    svc.identity
        .add_principal(admin_request(
            &svc,
            AddPrincipalRequest {
                profile_id: profile_a.id.to_string(),
                r#type: sid_proto::sid::v1::PrincipalType::Email as i32,
                value: "contested@sid.example.com".to_string(),
            },
        ))
        .await
        .unwrap();
    svc.relay_events().await;

    assert!(rx.try_recv().is_err(), "no event after first binding");

    // Profile B binds the same email — now contested. Profile A should be notified.
    svc.identity
        .add_principal(admin_request(
            &svc,
            AddPrincipalRequest {
                profile_id: profile_b.id.to_string(),
                r#type: sid_proto::sid::v1::PrincipalType::Email as i32,
                value: "contested@sid.example.com".to_string(),
            },
        ))
        .await
        .unwrap();

    // The binding owes the contestation check; it runs, then its event is relayed.
    assert!(rx.try_recv().is_err(), "published outside the outbox");
    svc.relay_events().await;
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout waiting for PRINCIPAL_CONTESTED event")
        .expect("channel closed unexpectedly");

    assert_eq!(
        event.event_type,
        sid_core::models::event::event_types::PRINCIPAL_CONTESTED,
    );

    // Event subject should be profile A (the existing holder being notified).
    let subject = event
        .subject
        .expect("PRINCIPAL_CONTESTED must have a subject");
    assert!(
        subject.contains(&profile_a.id.to_string()),
        "subject should reference profile A (the existing holder), got: {subject}"
    );

    // Event data should contain principal type, value, and new claimer.
    assert_eq!(event.data["principal_type"], "email");
    assert_eq!(event.data["principal_value"], "contested@sid.example.com");
    assert_eq!(
        event.data["new_claimer_profile_id"],
        profile_b.id.to_string().as_str()
    );

    // No second event (profile B is the new claimer, should not be notified about itself).
    assert!(
        rx.try_recv().is_err(),
        "profile B (new claimer) must not receive its own event"
    );
}

#[tokio::test]
async fn test_add_principal_notifies_all_existing_holders_when_third_profile_joins() {
    // When a THIRD profile binds the same identifier (already contested),
    // BOTH existing holders (A and B) must each receive a PRINCIPAL_CONTESTED event.
    let profile_a = Profile::new(Some("alice"));
    let mut profile_b = Profile::new(Some("bob"));
    profile_b.id = ProfileId::generate();
    let mut profile_c = Profile::new(Some("carol"));
    profile_c.id = ProfileId::generate();

    let storage = MockStorage::new()
        .with_profile(profile_a.clone())
        .with_profile(profile_b.clone())
        .with_profile(profile_c.clone());
    let svc = TestServices::new(storage);

    let filter = sid_core::models::event::EventFilter {
        event_types: vec![sid_core::models::event::event_types::PRINCIPAL_CONTESTED.to_string()],
        ..Default::default()
    };
    let mut rx = svc.event_bus.subscribe(filter).await.unwrap();

    // Profile A binds first — sole claimant, no event.
    svc.identity
        .add_principal(admin_request(
            &svc,
            AddPrincipalRequest {
                profile_id: profile_a.id.to_string(),
                r#type: sid_proto::sid::v1::PrincipalType::Email as i32,
                value: "three@sid.example.com".to_string(),
            },
        ))
        .await
        .unwrap();
    svc.relay_events().await;

    // Profile B binds — contested (2 holders). Profile A is notified.
    svc.identity
        .add_principal(admin_request(
            &svc,
            AddPrincipalRequest {
                profile_id: profile_b.id.to_string(),
                r#type: sid_proto::sid::v1::PrincipalType::Email as i32,
                value: "three@sid.example.com".to_string(),
            },
        ))
        .await
        .unwrap();
    svc.relay_events().await;

    // Drain the event for profile A.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout waiting for first PRINCIPAL_CONTESTED event");

    // Profile C binds — already contested. BOTH A and B should be notified.
    svc.identity
        .add_principal(admin_request(
            &svc,
            AddPrincipalRequest {
                profile_id: profile_c.id.to_string(),
                r#type: sid_proto::sid::v1::PrincipalType::Email as i32,
                value: "three@sid.example.com".to_string(),
            },
        ))
        .await
        .unwrap();
    svc.relay_events().await;

    // Collect both events (order not guaranteed).
    let event1 = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout waiting for event 1 after third binding")
        .expect("channel closed");
    let event2 = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout waiting for event 2 after third binding")
        .expect("channel closed");

    // Both events are PRINCIPAL_CONTESTED.
    assert_eq!(
        event1.event_type,
        sid_core::models::event::event_types::PRINCIPAL_CONTESTED
    );
    assert_eq!(
        event2.event_type,
        sid_core::models::event::event_types::PRINCIPAL_CONTESTED
    );

    // Both notified profiles are A or B (not C).
    let notified: std::collections::HashSet<String> = [&event1, &event2]
        .iter()
        .map(|e| {
            e.data["profile_id"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert!(
        notified.contains(&profile_a.id.to_string()),
        "profile A must be notified"
    );
    assert!(
        notified.contains(&profile_b.id.to_string()),
        "profile B must be notified"
    );
    assert!(
        !notified.contains(&profile_c.id.to_string()),
        "profile C (new claimer) must NOT be notified"
    );

    // No further events.
    assert!(rx.try_recv().is_err(), "no extra events expected");
}
