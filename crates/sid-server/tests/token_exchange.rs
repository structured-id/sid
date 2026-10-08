// SPDX-License-Identifier: AGPL-3.0-only
//! Token exchange / impersonation (RFC 8693): a machine user acts for a user
//! only with an admin grant, only for a user's live sign-in, and only for as
//! long as the recorded impersonation session exists.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token, issue_token_with_session, test_profile};
use sid_core::models::{Profile, ProfileStatus, Session};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Helper: create a machine user + client_secret credential for token exchange tests.
fn setup_machine_user_for_exchange(
    storage: MockStorage,
    target_profile: &Profile,
) -> (MockStorage, String) {
    use sha2::{Digest, Sha256};
    use sid_core::models::ProjectId;
    use sid_core::models::machine_user::*;

    let raw_secret = "test-machine-secret-12345";
    let secret_hash = format!("{:x}", Sha256::digest(raw_secret.as_bytes()));

    let mu = MachineUser::new(
        ProjectId::system(),
        "mu_test_exchange",
        "Test Exchange Bot",
        OwnerType::System,
        "system",
    );
    let mu_id = mu.id;

    let cred = MachineUserCredential::new(
        mu_id,
        "kid_test_exchange",
        MachineCredentialType::ClientSecret,
        secret_hash,
    );

    let grant = sid_core::models::ImpersonationGrant::new(
        mu_id,
        sid_core::models::ImpersonationTargetType::User,
        target_profile.id.to_string(),
        vec!["openid".to_string(), "profile".to_string()],
    );

    let storage = storage
        .with_machine_user(mu)
        .with_machine_credential(cred)
        .with_impersonation_grant(grant);

    (storage, raw_secret.to_string())
}

/// Exchange `subject_token` as the test machine user, at the token endpoint
/// of the installation's issuer.
fn exchange(
    svc: &TestServices,
    secret: &str,
    subject_token: String,
    scope: &str,
) -> Request<OAuth2TokenRequest> {
    Request::new(OAuth2TokenRequest {
        grant_type: TOKEN_EXCHANGE.to_string(),
        client_id: Some("mu_test_exchange".to_string()),
        client_secret: Some(secret.to_string()),
        subject_token: Some(subject_token),
        subject_token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
        scope: Some(scope.to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    })
}

/// Indicator of the API the test machine user calls.
const ORDERS: &str = "https://resources.example/orders";

/// A client_credentials request of the test machine user at `issuer_handle`
/// for the resources `resource` names.
fn machine_credentials(
    secret: &str,
    issuer_handle: String,
    resource: &[&str],
) -> Request<OAuth2TokenRequest> {
    Request::new(OAuth2TokenRequest {
        grant_type: "client_credentials".to_string(),
        client_id: Some("mu_test_exchange".to_string()),
        client_secret: Some(secret.to_string()),
        issuer_handle,
        resource: resource.iter().map(|r| r.to_string()).collect(),
        ..Default::default()
    })
}

/// Register the Orders API under the installation's issuer; with `scopes`,
/// give the test machine user access to it.
async fn orders_api(svc: &TestServices, scopes: Option<&[&str]>) {
    use sid_core::models::{
        Application, ApplicationId, AuditEntry, ProjectId, ProtectedResource, ResourceAccess,
        ResourceId, ResourceIndicator, ResourceState,
    };
    let now = chrono::Utc::now();
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: "Orders API".into(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: svc.issuer.id,
        indicator: ResourceIndicator::parse(ORDERS).unwrap(),
        scopes: vec!["orders.read".into(), "orders.write".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    svc.storage
        .create_application(
            &app,
            None,
            Some(&resource),
            AuditEntry::system("test", "api").into(),
        )
        .await
        .unwrap();
    if let Some(scopes) = scopes {
        svc.storage
            .set_resource_access(
                &ResourceAccess {
                    client_id: "mu_test_exchange".into(),
                    resource_id: resource.id,
                    scopes: scopes.iter().map(|s| s.to_string()).collect(),
                    created_at: now,
                },
                AuditEntry::system("test", "access").into(),
            )
            .await
            .unwrap();
    }
}

/// A machine user belongs to the installation, so the installation's issuer
/// issues its token: that issuer's `iss`, signed with its key, for the API
/// the machine user names and was given access to (RFC 8707 §2): `aud` the
/// API, `sub` the machine user's ID, `client_id` its client_id, `sid` the
/// credential it authenticated with (the API checks both again), scope only
/// what its access grants.
#[tokio::test]
async fn test_machine_credentials_are_issued_by_the_installation_issuer() {
    let profile = test_profile();
    let (storage, secret) =
        setup_machine_user_for_exchange(MockStorage::new().with_profile(profile.clone()), &profile);
    let svc = TestServices::new(storage);
    orders_api(&svc, Some(&["orders.read"])).await;

    let body = svc
        .auth
        .o_auth2_token(machine_credentials(
            &secret,
            svc.issuer.handle.to_string(),
            &[ORDERS],
        ))
        .await
        .unwrap()
        .into_inner();

    let claims = svc
        .issuers
        .verifier(&svc.issuer)
        .await
        .unwrap()
        .validate_access_token_for(&body.access_token, ORDERS)
        .expect("signed by the installation's issuer for the API");
    assert_eq!(claims.iss, svc.issuer.canonical_url);
    let machine = svc
        .storage
        .get_machine_user_by_client_id("mu_test_exchange")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claims.sub, machine.id.to_string());
    assert_eq!(claims.client_id.as_deref(), Some("mu_test_exchange"));
    assert_eq!(claims.sid, "kid_test_exchange");
    assert!(claims.pid.is_none());
    assert_eq!(claims.scope, "orders.read");
    assert_eq!(body.scope.as_deref(), Some("orders.read"));
}

/// Introspection reports a token active only while the OAuth client that
/// requested it is registered and active: deactivating the client ends the
/// grants its tokens rest on (resource SDK token-state contract), and
/// activating it again restores them.
#[tokio::test]
async fn introspection_reflects_the_requesting_clients_state() {
    use sid_core::models::{AuditEntry, ResourceAccess, RoleAssignmentPrincipal};
    const WORKER: &str = "orders-worker";
    const WORKER_SECRET: &str = "orders-worker-secret-0123456789";

    let mut worker = common::confidential_client();
    worker.client_id = WORKER.into();
    worker.client_secret_hash = Some(
        sid_authn::oauth2::OAuth2Server::hash_client_secret(WORKER_SECRET)
            .unwrap()
            .into_bytes(),
    );
    worker.grant_types = vec!["client_credentials".into()];
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(common::confidential_client())
            .with_client(worker),
    );
    orders_api(&svc, None).await;
    let resource = svc
        .storage
        .protected_resource_by_indicator(
            svc.issuer.id,
            &sid_core::models::ResourceIndicator::parse(ORDERS).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let audit = || AuditEntry::system("test", "client").into();
    svc.storage
        .set_resource_access(
            &ResourceAccess {
                client_id: WORKER.into(),
                resource_id: resource.id,
                scopes: vec!["orders.read".into()],
                created_at: chrono::Utc::now(),
            },
            audit(),
        )
        .await
        .unwrap();
    common::grant_inspection(
        &svc,
        RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        resource.id,
    )
    .await;
    let token = svc
        .auth
        .o_auth2_token(common::as_client(
            OAuth2TokenRequest {
                grant_type: "client_credentials".to_string(),
                issuer_handle: svc.issuer.handle.to_string(),
                resource: vec![ORDERS.to_string()],
                ..Default::default()
            },
            WORKER,
            WORKER_SECRET,
        ))
        .await
        .unwrap()
        .into_inner()
        .access_token;
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
    let set_active = |active: bool| {
        let storage = svc.storage.clone();
        async move {
            let mut client = storage.get_oauth2_client(WORKER).await.unwrap().unwrap();
            client.active = active;
            assert!(
                storage
                    .update_oauth2_client(&client, audit())
                    .await
                    .unwrap()
            );
        }
    };

    assert!(active().await, "a fresh client token is active");
    set_active(false).await;
    assert!(!active().await, "deactivated client");
    set_active(true).await;
    assert!(active().await, "activated again");
}

/// Introspection reports a machine's token active only while the machine and
/// the credential it was issued for are usable now, read from the store and
/// not only from the revocation cache: a suspended or expired machine, or a
/// revoked or expired credential, makes its token inactive (resource SDK
/// token-state contract), and a restored machine makes it active again.
#[tokio::test]
async fn introspection_reflects_the_machines_current_state() {
    use sid_core::models::{AuditEntry, MachineUserStatus, RoleAssignmentPrincipal};
    let profile = test_profile();
    let (storage, secret) =
        setup_machine_user_for_exchange(MockStorage::new().with_profile(profile.clone()), &profile);
    let svc = TestServices::new(storage.with_client(common::confidential_client()));
    orders_api(&svc, Some(&["orders.read"])).await;
    let resource = svc
        .storage
        .protected_resource_by_indicator(
            svc.issuer.id,
            &sid_core::models::ResourceIndicator::parse(ORDERS).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    common::grant_inspection(
        &svc,
        RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        resource.id,
    )
    .await;
    let token = svc
        .auth
        .o_auth2_token(machine_credentials(
            &secret,
            svc.issuer.handle.to_string(),
            &[ORDERS],
        ))
        .await
        .unwrap()
        .into_inner()
        .access_token;
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
    let audit = || AuditEntry::system("test", "machine").into();
    let machine = svc
        .storage
        .get_machine_user_by_client_id("mu_test_exchange")
        .await
        .unwrap()
        .unwrap();
    assert!(active().await, "a fresh machine token is active");

    let moved = |from, to| {
        let storage = svc.storage.clone();
        async move {
            assert!(
                storage
                    .transition_machine_user(machine.id, from, to, audit())
                    .await
                    .unwrap()
            );
        }
    };
    moved(MachineUserStatus::Active, MachineUserStatus::Suspended).await;
    assert!(!active().await, "suspended machine");
    moved(MachineUserStatus::Suspended, MachineUserStatus::Active).await;
    assert!(active().await, "restored machine");

    let mut expired = machine.clone();
    expired.expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
    assert!(
        svc.storage
            .update_machine_user(&expired, audit())
            .await
            .unwrap()
    );
    assert!(!active().await, "expired machine");
    expired.expires_at = None;
    assert!(
        svc.storage
            .update_machine_user(&expired, audit())
            .await
            .unwrap()
    );
    assert!(active().await, "machine without expiry");

    assert!(
        svc.storage
            .revoke_machine_credential(machine.id, "kid_test_exchange", audit())
            .await
            .unwrap()
    );
    assert!(!active().await, "revoked credential");
}

/// A machine user has no default target and obtains nothing for an API it
/// was not given access to: both are `invalid_target` (RFC 8707 §2).
#[tokio::test]
async fn test_machine_credentials_need_a_permitted_target() {
    let profile = test_profile();
    let (storage, secret) =
        setup_machine_user_for_exchange(MockStorage::new().with_profile(profile.clone()), &profile);
    let svc = TestServices::new(storage);
    orders_api(&svc, None).await;

    for resource in [&[][..], &[ORDERS][..]] {
        let err = svc
            .auth
            .o_auth2_token(machine_credentials(
                &secret,
                svc.issuer.handle.to_string(),
                resource,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{resource:?}");
        assert_eq!(
            common::oauth_error(&err).as_deref(),
            Some("invalid_target"),
            "{resource:?}"
        );
    }
}

/// At an endpoint of an issuer that does not serve it the machine user is
/// unknown, whatever its secret.
#[tokio::test]
async fn test_machine_credentials_at_another_issuer_are_refused() {
    let profile = test_profile();
    let (storage, secret) =
        setup_machine_user_for_exchange(MockStorage::new().with_profile(profile.clone()), &profile);
    let svc = TestServices::new(storage);

    let err = svc
        .auth
        .o_auth2_token(machine_credentials(
            &secret,
            sid_core::models::IssuerHandle::generate().to_string(),
            &[ORDERS],
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_token_exchange_happy_path() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);

    // Issue a valid access token for the target user (this is the subject_token).
    let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Perform token exchange.
    let resp = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            client_id: Some("mu_test_exchange".to_string()),
            client_secret: Some(secret),
            subject_token: Some(subject_token),
            subject_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            scope: Some("openid".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap();

    let body = resp.into_inner();
    assert_eq!(body.token_type, "Bearer");
    assert_eq!(body.expires_in, 300); // IMPERSONATION_MAX_LIFETIME_SECONDS
    assert!(body.refresh_token.is_none()); // No refresh for impersonation
    assert_eq!(body.scope.as_deref(), Some("openid"));
    // RFC 8693 §2.2.1: the response names the type of the issued token.
    assert_eq!(body.issued_token_type.as_deref(), Some(ACCESS_TOKEN_TYPE));

    // Validate the impersonation token — sub = target, act.sub = machine user.
    let claims = svc
        .jwt
        .validate_access_token(&body.access_token)
        .expect("impersonation token should be valid");
    assert_eq!(claims.sub, profile.id.to_string());
    assert!(claims.act.is_some(), "act claim must be present");
    assert_eq!(claims.act.unwrap().sub, "mu_test_exchange");
}

#[tokio::test]
async fn test_token_exchange_missing_subject_token() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);

    let err = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            client_id: Some("mu_test_exchange".to_string()),
            client_secret: Some(secret),
            // subject_token missing
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("subject_token"));
}

#[tokio::test]
async fn test_token_exchange_wrong_secret() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, _secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);

    let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let err = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            client_id: Some("mu_test_exchange".to_string()),
            client_secret: Some("wrong-secret".to_string()),
            subject_token: Some(subject_token),
            subject_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_token_exchange_no_grant_for_target() {
    use sha2::{Digest, Sha256};
    use sid_core::models::ProjectId;
    use sid_core::models::machine_user::*;

    let target = test_profile();
    let raw_secret = "test-secret-no-grant";
    let secret_hash = format!("{:x}", Sha256::digest(raw_secret.as_bytes()));

    let mu = MachineUser::new(
        ProjectId::system(),
        "mu_no_grant",
        "No Grant Bot",
        OwnerType::System,
        "system",
    );
    let cred = MachineUserCredential::new(
        mu.id,
        "kid_no_grant",
        MachineCredentialType::ClientSecret,
        secret_hash,
    );
    // No impersonation grant created!

    let storage = MockStorage::new()
        .with_profile(target.clone())
        .with_machine_user(mu)
        .with_machine_credential(cred);
    let svc = TestServices::new(storage);

    let subject_token = issue_token(&svc.jwt, &target, &["openid".to_string()]);

    let err = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            client_id: Some("mu_no_grant".to_string()),
            client_secret: Some(raw_secret.to_string()),
            subject_token: Some(subject_token),
            subject_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    // RFC 8693 §2.2.2: a subject the client may not act for is unacceptable
    // by policy, `invalid_request`.
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let oauth_error = tonic_types::StatusExt::get_details_error_info(&err)
        .and_then(|info| info.metadata.get("oauthError").cloned());
    assert_eq!(oauth_error.as_deref(), Some("invalid_request"), "{err:?}");
}

#[tokio::test]
async fn test_token_exchange_scope_intersection() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);

    let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Request scope "admin" which is NOT in the grant (grant allows openid, profile).
    let err = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            client_id: Some("mu_test_exchange".to_string()),
            client_secret: Some(secret),
            subject_token: Some(subject_token),
            subject_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            scope: Some("admin".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    // Should fail because "admin" is not in grant.allowed_scopes
    assert!(
        err.code() == tonic::Code::InvalidArgument || err.code() == tonic::Code::PermissionDenied,
        "expected scope intersection error, got {:?}: {}",
        err.code(),
        err.message()
    );
}

/// An impersonation token cannot be exchanged again: otherwise the machine
/// could keep renewing it past its lifetime without the user ever signing in.
#[tokio::test]
async fn test_impersonation_token_cannot_be_renewed() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);
    let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let impersonation = svc
        .auth
        .o_auth2_token(exchange(&svc, &secret, subject_token, "openid"))
        .await
        .unwrap()
        .into_inner()
        .access_token;

    let err = svc
        .auth
        .o_auth2_token(exchange(&svc, &secret, impersonation, "openid"))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

/// A subject token whose session was revoked (sign-out, revocation) no longer
/// opens an impersonation.
#[tokio::test]
async fn test_revoked_subject_token_is_refused() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (subject_token, session) =
        issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.revocation_cache
        .revoke_session(session.id.to_string())
        .await
        .unwrap();

    let err = svc
        .auth
        .o_auth2_token(exchange(&svc, &secret, subject_token, "openid"))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

/// A suspended account cannot be acted for, even with a grant.
#[tokio::test]
async fn test_suspended_target_cannot_be_impersonated() {
    let mut profile = test_profile();
    let subject_token = {
        let svc = TestServices::new(MockStorage::new());
        issue_token(&svc.jwt, &profile, &["openid".to_string()])
    };
    profile.status = ProfileStatus::Suspended;
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);

    let err = svc
        .auth
        .o_auth2_token(exchange(&svc, &secret, subject_token, "openid"))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

/// Only an access token is issued: a request for another token type is
/// refused as `invalid_request` (RFC 8693 §2.1, §2.2.2), never answered with
/// an access token the client did not ask for.
#[tokio::test]
async fn test_exchange_refuses_another_requested_token_type() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);

    for wanted in [
        "urn:ietf:params:oauth:token-type:refresh_token",
        "urn:ietf:params:oauth:token-type:id_token",
    ] {
        let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
        let mut request = exchange(&svc, &secret, subject_token, "openid");
        request.get_mut().requested_token_type = Some(wanted.to_string());
        let err = svc.auth.o_auth2_token(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{wanted}");
        assert_eq!(
            common::oauth_error(&err).as_deref(),
            Some("invalid_request"),
            "{wanted}"
        );
    }

    let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let mut request = exchange(&svc, &secret, subject_token, "openid");
    request.get_mut().requested_token_type = Some(ACCESS_TOKEN_TYPE.to_string());
    let body = svc.auth.o_auth2_token(request).await.unwrap().into_inner();
    assert_eq!(body.issued_token_type.as_deref(), Some(ACCESS_TOKEN_TYPE));
}

/// A target named by `resource` or `audience` (RFC 8693 §2.1) is never
/// ignored: an exchange issues only the installation's own impersonation
/// token, so a request for a registered API, even one the machine user may
/// call, or for two different targets is `invalid_target` instead of a token
/// for another audience than asked.
#[tokio::test]
async fn test_exchange_does_not_ignore_a_named_target() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);
    orders_api(&svc, Some(&["orders.read"])).await;

    let named: [(&[&str], &[&str]); 4] = [
        (&[ORDERS], &[]),
        (&[], &[ORDERS]),
        (&[ORDERS], &[ORDERS]),
        (&[ORDERS], &["https://resources.example/wiki"]),
    ];
    for (resource, audience) in named {
        let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
        let mut request = exchange(&svc, &secret, subject_token, "openid");
        request.get_mut().resource = resource.iter().map(|r| r.to_string()).collect();
        request.get_mut().audience = audience.iter().map(|a| a.to_string()).collect();
        let err = svc.auth.o_auth2_token(request).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::InvalidArgument,
            "{resource:?} {audience:?}"
        );
        assert_eq!(
            common::oauth_error(&err).as_deref(),
            Some("invalid_target"),
            "{resource:?} {audience:?}"
        );
    }
}

/// The impersonation never exceeds what the user's own token holds.
#[tokio::test]
async fn test_impersonation_scopes_stay_within_the_user_token() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);
    let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let body = svc
        .auth
        .o_auth2_token(exchange(&svc, &secret, subject_token, "openid profile"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(body.scope.as_deref(), Some("openid"));
}

/// The impersonation is recorded as a session of the target and audited with
/// it; the token belongs to that session, so the target's revocation (which
/// revokes every session of the profile) ends it.
#[tokio::test]
async fn test_impersonation_is_a_recorded_and_audited_session() {
    let profile = test_profile();
    let storage = MockStorage::new().with_profile(profile.clone());
    let (storage, secret) = setup_machine_user_for_exchange(storage, &profile);
    let svc = TestServices::new(storage);
    let subject_token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    let token = svc
        .auth
        .o_auth2_token(exchange(&svc, &secret, subject_token, "openid"))
        .await
        .unwrap()
        .into_inner()
        .access_token;

    let claims = svc.jwt.validate_access_token(&token).unwrap();
    let session_id = sid_core::models::SessionId::parse(&claims.sid).expect("token has a session");
    let session = svc
        .storage
        .get_session(session_id)
        .await
        .unwrap()
        .expect("impersonation session stored");
    assert_eq!(session.profile_id, profile.id);
    assert_eq!(session.client_id.as_deref(), Some("mu_test_exchange"));
    assert_eq!(session.expires_at.timestamp(), claims.exp);
    let audits = svc.mock_storage.session_audits();
    let audit = audits
        .iter()
        .find(|a| a.action == "sid.token.impersonation.v1")
        .expect("impersonation audited with its session");
    assert_eq!(audit.resource, format!("profile:{}", profile.id));
}
