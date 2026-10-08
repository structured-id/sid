// SPDX-License-Identifier: AGPL-3.0-only
//! The account integration's connection details reach only the holder of one
//! of its registered keys, and only while the integration is provisioned and
//! enabled (auth/session-management.md, system account integration).

mod common;

use base64::Engine;
use common::TestServices;
use common::mock_storage::MockStorage;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sid_authn::system_integration::{AccountSettings, ensure_account_integration};
use sid_core::models::ClientKeySet;
use sid_proto::sid::v1::system_integration_service_server::SystemIntegrationService;
use sid_proto::sid::v1::{AccountConnection, GetAccountConnectionRequest};
use sid_server::grpc::system_integration_service::SystemIntegrationServiceImpl;
use tonic::Request;

const ED_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGnMIVUgwI0tTO1AANoNzICml1zLy8M4WqrJlomrTGlU\n-----END PRIVATE KEY-----";
const ED_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAqK9dvWXRiLy73AXFvVRAMzmlQwKF6q/R/UJmjngfLLs=\n-----END PUBLIC KEY-----";
/// A second Ed25519 key, registered by nobody.
const OTHER_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDxNJ3wBtW7Ec2p2Kn0cYyAqJmM5DW9t0ByZxcLfJ8kX\n-----END PRIVATE KEY-----";
const INSTALLATION: &str = "https://sid.example.com";
const ACCOUNT_URL: &str = "https://account.sid.example.com";
const KID: &str = "bff-1";

fn key_set() -> ClientKeySet {
    let body: String = ED_PUBLIC_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der[12..]);
    ClientKeySet::try_from(serde_json::json!({
        "keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": KID}]
    }))
    .unwrap()
}

/// A proof of `kid` for `audience`, signed with `private_pem`.
fn proof(private_pem: &str, kid: &str, audience: &str, jti: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": kid, "sub": kid, "aud": audience, "iat": now, "exp": now + 60, "jti": jti,
    });
    let header = Header {
        kid: Some(kid.to_owned()),
        ..Header::new(Algorithm::EdDSA)
    };
    encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn audience() -> String {
    SystemIntegrationServiceImpl::account_proof_audience(INSTALLATION)
}

fn service(svc: &TestServices) -> SystemIntegrationServiceImpl {
    SystemIntegrationServiceImpl::new(svc.storage.clone(), INSTALLATION.into(), svc.cache.clone())
}

async fn provisioned() -> TestServices {
    provisioned_over(MockStorage::new().with_system_project()).await
}

async fn provisioned_over(storage: MockStorage) -> TestServices {
    let svc = TestServices::new(storage);
    let settings = AccountSettings::new(ACCOUNT_URL, key_set()).unwrap();
    ensure_account_integration(svc.storage.as_ref(), &svc.issuer, INSTALLATION, &settings)
        .await
        .unwrap();
    svc
}

async fn connect(
    integrations: &SystemIntegrationServiceImpl,
    proof: String,
) -> Result<AccountConnection, tonic::Status> {
    integrations
        .get_account_connection(Request::new(GetAccountConnectionRequest { proof }))
        .await
        .map(tonic::Response::into_inner)
}

/// The key holder learns exactly what it was provisioned with: the issuer's
/// canonical URL, its client, the account API, its scopes and its callback.
#[tokio::test]
async fn the_key_holder_gets_its_connection() {
    let svc = provisioned().await;
    let connection = connect(
        &service(&svc),
        proof(ED_PRIVATE_PEM, KID, &audience(), "j1"),
    )
    .await
    .unwrap();
    let integration = sid_authn::system_integration::account_integration(svc.storage.as_ref())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(connection.issuer, svc.issuer.canonical_url);
    assert_eq!(connection.client_id, integration.client.client_id);
    assert_eq!(connection.resource, "https://sid.example.com/account");
    assert!(connection.scopes.contains(&"account".to_owned()));
    assert!(connection.scopes.contains(&"openid".to_owned()));
    assert_eq!(
        connection.redirect_uri,
        "https://account.sid.example.com/auth/callback"
    );
    assert_eq!(connection.token_endpoint_auth_method, "private_key_jwt");
}

/// A proof by an unregistered key, for another audience, or used twice
/// learns nothing.
#[tokio::test]
async fn a_bad_proof_learns_nothing() {
    let svc = provisioned().await;
    let integrations = service(&svc);
    for bad in [
        proof(OTHER_PRIVATE_PEM, KID, &audience(), "b1"),
        proof(ED_PRIVATE_PEM, "unregistered", &audience(), "b2"),
        proof(ED_PRIVATE_PEM, KID, "https://sid.example.com/other", "b3"),
        "not-a-jwt".to_owned(),
    ] {
        let err = connect(&integrations, bad).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
    }
    let once = proof(ED_PRIVATE_PEM, KID, &audience(), "b4");
    connect(&integrations, once.clone()).await.unwrap();
    let err = connect(&integrations, once).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
}

/// A client assertion (RFC 7523 §3) of `client_id` for `audience`, signed
/// with `private_pem` under the registered kid.
fn client_assertion(private_pem: &str, client_id: &str, audience: &str, jti: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client_id, "sub": client_id, "aud": audience,
        "iat": now, "exp": now + 60, "jti": jti,
    });
    let header = Header {
        kid: Some(KID.to_owned()),
        ..Header::new(Algorithm::EdDSA)
    };
    encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// The payload of a JWT, unverified: what its holder was issued.
fn payload(jwt: &str) -> serde_json::Value {
    let body = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .unwrap(),
    )
    .unwrap()
}

fn bearer<T>(msg: T, token: &str) -> Request<T> {
    let mut request = Request::new(msg);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

/// A code for the account API: `profile`'s fresh IdP session authorizes the
/// account client, as the sign-in surface does for the BFF.
async fn authorize_account(
    svc: &TestServices,
    connection: &AccountConnection,
    profile: &sid_core::models::Profile,
) -> String {
    use sid_proto::sid::v1::auth_service_server::AuthService;
    use sid_proto::sid::v1::o_auth2_authorize_response::Result as Authorized;
    let session = common::fresh_token(svc, profile).await;
    let request = bearer(
        sid_proto::sid::v1::OAuth2AuthorizeRequest {
            client_id: connection.client_id.clone(),
            redirect_uri: connection.redirect_uri.clone(),
            response_type: "code".into(),
            scope: Some(connection.scopes.join(" ")),
            state: Some("s".into()),
            nonce: Some("n".into()),
            code_challenge: Some(common::oauth_client::CODE_CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            issuer_handle: svc.issuer.handle.to_string(),
            resource: vec![connection.resource.clone()],
            ..Default::default()
        },
        &session,
    );
    match svc
        .auth
        .o_auth2_authorize(request)
        .await
        .unwrap()
        .into_inner()
        .result
    {
        Some(Authorized::AuthorizationCode(code)) => code,
        other => panic!("expected a code, got {other:?}"),
    }
}

/// The BFF's redemption of `code` with `assertion`.
async fn redeem_account(
    svc: &TestServices,
    connection: &AccountConnection,
    code: String,
    assertion: Option<String>,
) -> Result<sid_proto::sid::v1::OAuth2TokenResponse, tonic::Status> {
    use sid_proto::sid::v1::auth_service_server::AuthService;
    const ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    svc.auth
        .o_auth2_token(Request::new(sid_proto::sid::v1::OAuth2TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(code),
            redirect_uri: Some(connection.redirect_uri.clone()),
            client_id: Some(connection.client_id.clone()),
            code_verifier: Some(common::oauth_client::CODE_VERIFIER.into()),
            client_assertion_type: assertion.as_ref().map(|_| ASSERTION.to_owned()),
            client_assertion: assertion,
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .map(tonic::Response::into_inner)
}

/// The account API tokens the BFF holds for `profile`.
async fn account_tokens(
    svc: &TestServices,
    profile: &sid_core::models::Profile,
    jti: &str,
) -> (AccountConnection, sid_proto::sid::v1::OAuth2TokenResponse) {
    let connection = connect(
        &service(svc),
        proof(ED_PRIVATE_PEM, KID, &audience(), &format!("p-{jti}")),
    )
    .await
    .unwrap();
    let code = authorize_account(svc, &connection, profile).await;
    let assertion = client_assertion(
        ED_PRIVATE_PEM,
        &connection.client_id,
        &format!("{}/oauth2/token", connection.issuer),
        jti,
    );
    let tokens = redeem_account(svc, &connection, code, Some(assertion))
        .await
        .unwrap();
    (connection, tokens)
}

/// The BFF's path: a signed-in user authorizes the account client for the
/// account API, and the BFF redeems the code with an assertion of its key.
/// The token is for the account API, names the client, and carries no
/// source `pid`. The code is refused without the assertion, with another
/// key's assertion, or with one made for another token endpoint.
#[tokio::test]
async fn the_bff_redeems_a_code_for_the_account_api() {
    let profile = common::test_profile();
    let svc = provisioned_over(
        MockStorage::new()
            .with_system_project()
            .with_profile(profile.clone()),
    )
    .await;
    let connection = connect(
        &service(&svc),
        proof(ED_PRIVATE_PEM, KID, &audience(), "c1"),
    )
    .await
    .unwrap();
    let token_endpoint = format!("{}/oauth2/token", connection.issuer);

    for refused in [
        None,
        Some(client_assertion(
            OTHER_PRIVATE_PEM,
            &connection.client_id,
            &token_endpoint,
            "r1",
        )),
        Some(client_assertion(
            ED_PRIVATE_PEM,
            &connection.client_id,
            "https://other.example/oauth2/token",
            "r2",
        )),
    ] {
        let code = authorize_account(&svc, &connection, &profile).await;
        let err = redeem_account(&svc, &connection, code, refused)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
    }

    let (connection, tokens) = account_tokens(&svc, &profile, "ok").await;
    let claims = payload(&tokens.access_token);
    assert_eq!(claims["aud"], serde_json::json!([connection.resource]));
    assert_eq!(claims["client_id"], connection.client_id);
    assert_eq!(claims["iss"], connection.issuer);
    assert!(claims.get("pid").is_none(), "no source pid: {claims}");
    assert_eq!(claims["scope"], "account");
    assert!(tokens.refresh_token.is_some());
}

/// The account API admits the BFF's token as the user it was issued for,
/// for the user's own account only: an administrator's account token opens
/// no administration, and it never stands for the IdP session (no new codes,
/// no step-up). A UserInfo token, an ID token, and a token of a revoked
/// session are refused.
#[tokio::test]
async fn the_account_api_admits_the_bffs_token_for_the_users_own_account() {
    use sid_proto::sid::v1::auth_service_server::AuthService;
    use sid_proto::sid::v1::identity_service_server::IdentityService;
    use sid_proto::sid::v1::project_service_server::ProjectService;
    use sid_proto::sid::v1::{
        GetCurrentProfileRequest, ListProjectsRequest, OAuth2AuthorizeRequest, VerifyTotpRequest,
    };

    let mut profile = common::test_profile();
    profile.roles = vec!["admin".into()];
    let svc = provisioned_over(
        MockStorage::new()
            .with_system_project()
            .with_profile(profile.clone())
            .with_client(common::test_client()),
    )
    .await;
    let (connection, tokens) = account_tokens(&svc, &profile, "api").await;
    let token = tokens.access_token;

    // The user's own account.
    let own = svc
        .identity
        .get_current_profile(bearer(GetCurrentProfileRequest {}, &token))
        .await
        .unwrap()
        .into_inner()
        .profile
        .unwrap();
    assert_eq!(own.id, profile.id.to_string());

    // No administration through the account client, whatever the user's role.
    let err = svc
        .project
        .list_projects(bearer(
            ListProjectsRequest {
                page_size: 10,
                page_token: String::new(),
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");

    // Never the IdP session: no codes for other clients, no step-up.
    let err = svc
        .auth
        .o_auth2_authorize(bearer(
            OAuth2AuthorizeRequest {
                client_id: connection.client_id.clone(),
                redirect_uri: connection.redirect_uri.clone(),
                response_type: "code".into(),
                scope: Some("openid".into()),
                code_challenge: Some(common::oauth_client::CODE_CHALLENGE.into()),
                code_challenge_method: Some("S256".into()),
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    let err = svc
        .auth
        .verify_totp(bearer(
            VerifyTotpRequest {
                code: "123456".into(),
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");

    // The ID token of the same grant is no access token.
    let id_token = tokens.id_token.expect("an ID token for openid");
    let err = svc
        .identity
        .get_current_profile(bearer(GetCurrentProfileRequest {}, &id_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");

    // A token another client obtained for UserInfo is not for the account API.
    let code = common::oauth_client::authorize_code(&svc, &profile).await;
    let userinfo = svc
        .auth
        .o_auth2_token(common::oauth_client::code_exchange(&svc, &code))
        .await
        .unwrap()
        .into_inner()
        .access_token;
    let err = svc
        .identity
        .get_current_profile(bearer(GetCurrentProfileRequest {}, &userinfo))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");

    // A revoked application session ends the token's use.
    let sid = payload(&token)["sid"].as_str().unwrap().to_owned();
    svc.revocation_cache.revoke_session(sid).await.unwrap();
    let err = svc
        .identity
        .get_current_profile(bearer(GetCurrentProfileRequest {}, &token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
}

fn admin<T>(svc: &TestServices, msg: T) -> Request<T> {
    let token = common::issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    let mut request = Request::new(msg);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

/// An administrator disables the integration but cannot delete it (the next
/// start would bring it back with new identifiers) or reshape its client,
/// resource or access, which follow the deployment.
#[tokio::test]
async fn the_integration_is_disabled_not_edited() {
    use sid_proto::sid::v1::project_service_server::ProjectService;
    use sid_proto::sid::v1::*;
    let svc = provisioned().await;
    let integration = sid_authn::system_integration::account_integration(svc.storage.as_ref())
        .await
        .unwrap()
        .unwrap();
    let client_id = integration.client.client_id.clone();
    let managed = |err: tonic::Status| {
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");
    };

    managed(
        svc.project
            .delete_application(admin(
                &svc,
                DeleteApplicationRequest {
                    id: integration.application.id.to_string(),
                },
            ))
            .await
            .unwrap_err(),
    );
    managed(
        svc.project
            .update_client_role(admin(
                &svc,
                UpdateClientRoleRequest {
                    client_id: client_id.clone(),
                    redirect_uris: vec!["https://evil.example/cb".into()],
                    ..Default::default()
                },
            ))
            .await
            .unwrap_err(),
    );
    managed(
        svc.project
            .remove_resource_access(admin(
                &svc,
                RemoveResourceAccessRequest {
                    client_id: client_id.clone(),
                    resource_id: integration.resource.id.to_string(),
                },
            ))
            .await
            .unwrap_err(),
    );
    managed(
        svc.project
            .update_resource_role(admin(
                &svc,
                UpdateResourceRoleRequest {
                    resource_id: integration.resource.id.to_string(),
                    scopes: Some(ScopeList {
                        scopes: vec!["everything".into()],
                    }),
                    state: None,
                },
            ))
            .await
            .unwrap_err(),
    );

    svc.project
        .update_client_role(admin(
            &svc,
            UpdateClientRoleRequest {
                client_id: client_id.clone(),
                active: Some(false),
                ..Default::default()
            },
        ))
        .await
        .unwrap();
    let stored = svc
        .storage
        .get_oauth2_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.active);
    assert_eq!(stored.redirect_uris, integration.client.redirect_uris);
}

/// Without a provisioned integration, or with its client disabled, there is
/// nothing to connect to, whatever the proof.
#[tokio::test]
async fn an_unavailable_integration_serves_nothing() {
    let bare = TestServices::new(MockStorage::new().with_system_project());
    let err = connect(
        &service(&bare),
        proof(ED_PRIVATE_PEM, KID, &audience(), "u1"),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");

    let svc = provisioned().await;
    let integration = sid_authn::system_integration::account_integration(svc.storage.as_ref())
        .await
        .unwrap()
        .unwrap();
    let mut disabled = integration.client;
    disabled.active = false;
    assert!(
        svc.storage
            .update_oauth2_client(
                &disabled,
                sid_core::models::AuditEntry::system("test", "disable").into()
            )
            .await
            .unwrap()
    );
    let err = connect(
        &service(&svc),
        proof(ED_PRIVATE_PEM, KID, &audience(), "u2"),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");
}
