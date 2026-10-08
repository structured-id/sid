// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::jwt::JwtService;
use sid_core::models::LoginStrategy;

fn create_test_jwt() -> Arc<JwtService> {
    let private_pem = include_bytes!("../../tests/fixtures/test_ed25519_private.pem");
    let public_pem = include_bytes!("../../tests/fixtures/test_ed25519_public.pem");
    Arc::new(
        JwtService::new(
            private_pem,
            public_pem,
            "https://sid.example.com".to_string(),
        )
        .expect("JWT creation failed"),
    )
}

fn create_test_client() -> OAuth2Client {
    OAuth2Client {
        client_id: "test-client".to_string(),
        project_id: sid_core::models::ProjectId::system(),
        application_id: sid_core::models::ApplicationId::generate(),
        default_resource: None,
        application_type: sid_core::models::ApplicationType::Spa,
        client_secret_hash: None, // public client
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
        allowed_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        client_name: "Test App".to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: sid_core::models::TokenEndpointAuthMethod::None,
        response_types: vec!["code".into()],
        subject_type: sid_core::models::SubjectType::Pairwise,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: Utc::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: sid_core::models::EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: None,
        revision: 0,
        created_at: Utc::now(),
    }
}

/// A target the test client has access to, granting `openid` and `orders.read`.
fn orders_target(client: &OAuth2Client) -> crate::target::Target {
    use sid_core::models::{
        IssuerId, ProtectedResource, ResourceAccess, ResourceId, ResourceIndicator, ResourceState,
    };
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(sid_core::models::ApplicationId::generate()),
        issuer_id: IssuerId::generate(),
        indicator: ResourceIndicator::parse(ORDERS).unwrap(),
        scopes: vec!["openid".into(), "orders.read".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let access = ResourceAccess {
        client_id: client.client_id.clone(),
        resource_id: resource.id,
        scopes: vec!["openid".into(), "orders.read".into()],
        created_at: Utc::now(),
    };
    crate::target::Target::from_parts(resource, access)
}

const ORDERS: &str = "https://resources.example/orders";

/// A password sign-in ten minutes ago.
fn test_authentication() -> sid_core::models::GrantAuthentication {
    sid_core::models::GrantAuthentication {
        session: sid_core::models::SessionId::generate(),
        authenticated_at: Utc::now() - chrono::Duration::minutes(10),
        amr: vec!["pwd".into()],
        assurance_level: sid_core::models::AuthLevel::Basic,
        elevation: None,
    }
}

fn create_test_profile() -> Profile {
    Profile::new(Some("alice"))
}

fn create_test_session(profile: &Profile) -> Session {
    Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    )
}

/// A complete, valid OIDC authorization request.
fn oidc_request() -> AuthorizeRequest {
    AuthorizeRequest {
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        response_type: "code".to_string(),
        scope: Some("openid profile".to_string()),
        state: Some("xyz".to_string()),
        code_challenge: Some(compute_s256_challenge("test-verifier")),
        code_challenge_method: Some("S256".to_string()),
        nonce: Some("n-0S6_WzA2Mj".to_string()),
    }
}

#[test]
fn test_validate_authorize_request() {
    let server = OAuth2Server::new(create_test_jwt());
    let client = create_test_client();

    let validated = server
        .validate_authorize_request(&client, &oidc_request())
        .expect("Validation should succeed");

    assert_eq!(validated.scopes, vec!["openid", "profile"]);
    assert_eq!(validated.state.as_deref(), Some("xyz"));
    assert_eq!(validated.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
}

#[test]
fn test_all_clients_require_pkce() {
    let server = OAuth2Server::new(create_test_jwt());
    let client = create_test_client();

    let req = AuthorizeRequest {
        code_challenge: None, // Missing PKCE — rejected for ALL clients
        code_challenge_method: None,
        ..oidc_request()
    };

    let result = server.validate_authorize_request(&client, &req);
    assert_eq!(result.unwrap_err(), AuthorizeError::PkceRequired);
}

/// A challenge without a method is a `plain` challenge (RFC 7636 §4.3), and
/// only S256 is accepted: the request is refused at the authorization
/// endpoint rather than failing later at the token endpoint.
#[test]
fn test_challenge_without_method_is_plain_and_refused() {
    let server = OAuth2Server::new(create_test_jwt());
    let client = create_test_client();
    for method in [None, Some("plain".to_string())] {
        let req = AuthorizeRequest {
            code_challenge_method: method,
            ..oidc_request()
        };
        let err = server
            .validate_authorize_request(&client, &req)
            .unwrap_err();
        assert_eq!(err, AuthorizeError::PkceMethodUnsupported);
        assert_eq!(err.oauth_error(), "invalid_request");
    }
}

/// `state` is required (CSRF protection for the client's redirect).
#[test]
fn test_state_is_required() {
    let server = OAuth2Server::new(create_test_jwt());
    let client = create_test_client();

    for state in [None, Some(String::new())] {
        let req = AuthorizeRequest {
            state,
            ..oidc_request()
        };
        let err = server
            .validate_authorize_request(&client, &req)
            .unwrap_err();
        assert_eq!(err, AuthorizeError::StateRequired);
        assert_eq!(err.oauth_error(), "invalid_request");
    }
}

/// `nonce` is required when `openid` is requested, and only then.
#[test]
fn test_nonce_required_for_openid() {
    let server = OAuth2Server::new(create_test_jwt());
    let client = create_test_client();

    let req = AuthorizeRequest {
        nonce: None,
        ..oidc_request()
    };
    assert_eq!(
        server
            .validate_authorize_request(&client, &req)
            .unwrap_err(),
        AuthorizeError::NonceRequired
    );
    // No scope means the default `openid`.
    let req = AuthorizeRequest {
        scope: None,
        nonce: None,
        ..oidc_request()
    };
    assert_eq!(
        server
            .validate_authorize_request(&client, &req)
            .unwrap_err(),
        AuthorizeError::NonceRequired
    );

    let req = AuthorizeRequest {
        scope: Some("profile".to_string()),
        nonce: None,
        ..oidc_request()
    };
    server
        .validate_authorize_request(&client, &req)
        .expect("plain OAuth2 request needs no nonce");
}

#[test]
fn test_invalid_redirect_uri() {
    let server = OAuth2Server::new(create_test_jwt());
    let client = create_test_client();

    let req = AuthorizeRequest {
        client_id: "test-client".to_string(),
        redirect_uri: "https://evil.com/callback".to_string(),
        // Also wrong: the redirect URI must be reported first, since every
        // other error would be sent to it.
        response_type: "token".to_string(),
        scope: None,
        state: None,
        code_challenge: Some("test".to_string()),
        code_challenge_method: Some("S256".to_string()),
        nonce: None,
    };

    let result = server.validate_authorize_request(&client, &req);
    assert_eq!(result.unwrap_err(), AuthorizeError::UnregisteredRedirectUri);
}

#[test]
fn test_auth_code_generation_and_pkce() {
    let server = OAuth2Server::new(create_test_jwt());
    let profile = create_test_profile();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = compute_s256_challenge(verifier);

    let validated = ValidatedAuthorizeRequest {
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        scopes: vec!["openid".to_string()],
        state: None,
        code_challenge: Some(challenge),
        nonce: Some("n-0S6_WzA2Mj".to_string()),
    };

    let resource = sid_core::models::ResourceId::generate();
    let authentication = test_authentication();
    let (raw_code, code_model) = server
        .generate_auth_code(profile.id, &validated, resource, authentication.clone())
        .expect("Code generation should succeed");

    assert!(!raw_code.is_empty());
    assert!(!code_model.used);
    assert!(code_model.code_challenge.is_some());
    // The code is bound to the target it was authorized for.
    assert_eq!(code_model.resource, resource);

    // Clone for the wrong-verifier test (exchange consumes the code)
    let code_for_wrong_verifier = code_model.clone();

    // Verify PKCE — consumes code_model
    let client = create_test_client();
    let exchanged = server
        .validate_code_exchange(
            &client,
            code_model,
            Some(verifier),
            "https://app.sid.example.com/callback",
        )
        .expect("PKCE validation should succeed");

    // ExchangedCode provides access to authorization data
    assert_eq!(exchanged.scopes(), &["openid"]);
    assert_eq!(exchanged.client_id(), "test-client");
    // The nonce reaches the token endpoint with the code.
    assert_eq!(exchanged.nonce(), Some("n-0S6_WzA2Mj"));
    // So does the authorizing session's authentication.
    assert_eq!(exchanged.authentication(), &authentication);

    // Wrong verifier should fail
    let result = server.validate_code_exchange(
        &client,
        code_for_wrong_verifier,
        Some("wrong-verifier"),
        "https://app.sid.example.com/callback",
    );
    assert!(result.is_err());
}

/// A code carrying no PKCE challenge is not exchanged, even without a verifier.
#[test]
fn test_code_without_pkce_is_not_exchanged() {
    let server = OAuth2Server::new(create_test_jwt());
    let profile = create_test_profile();
    let validated = ValidatedAuthorizeRequest {
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        scopes: vec!["openid".to_string()],
        state: Some("xyz".to_string()),
        code_challenge: None,
        nonce: Some("n".to_string()),
    };
    let (_, code) = server
        .generate_auth_code(
            profile.id,
            &validated,
            sid_core::models::ResourceId::generate(),
            test_authentication(),
        )
        .unwrap();

    let err = server
        .validate_code_exchange(
            &create_test_client(),
            code,
            None,
            "https://app.sid.example.com/callback",
        )
        .unwrap_err();

    assert!(err.to_string().contains("invalid_grant"), "{err}");
}

/// Tokens for an application are issued by its issuer: `iss` is the issuer
/// URL, the issuer's key signs them, and the installation's own session key
/// does not verify them. The access token is for the target resource: its
/// `aud` is the indicator, its `client_id` the requesting client, and its
/// scope only what the target grants; the refresh token keeps the target.
#[tokio::test]
async fn test_issue_tokens() {
    let jwt = create_test_jwt();
    let server = OAuth2Server::new(jwt.clone());
    let (issuers, issuer) = crate::test_support::installation_issuer().await;
    let signer = issuers.signer(&issuer).await.unwrap();
    let profile = create_test_profile();
    let session = create_test_session(&profile);
    let client = create_test_client();
    let target = orders_target(&client);
    let scopes = vec!["openid".to_string(), "profile".to_string()];

    let (response, refresh) = server
        .issue_tokens(
            &signer,
            &profile.id.to_string(),
            &profile,
            &session,
            &client,
            &target,
            &scopes,
            Some("nonce123"),
            None,
            None,
            None,
            None,
        )
        .expect("Token issuance should succeed");

    assert_eq!(response.token_type, "Bearer");
    assert!(response.refresh_token.is_some());
    assert!(!refresh.revoked);

    let verifier = issuers.verifier(&issuer).await.unwrap();
    let claims = verifier
        .validate_access_token_for(&response.access_token, ORDERS)
        .expect("the issuer's verifier accepts its access token for the resource");
    assert_eq!(claims.iss, issuer.canonical_url);
    assert_eq!(claims.aud, vec![ORDERS.to_string()]);
    assert_eq!(claims.client_id.as_deref(), Some("test-client"));
    // `profile` is not a scope of the resource.
    assert_eq!(claims.scope, "openid");
    assert_eq!(response.scope.as_deref(), Some("openid"));
    assert_eq!(refresh.resource, target.resource_id());
    assert_eq!(refresh.scopes, scopes);
    assert!(jwt.validate_access_token(&response.access_token).is_err());

    // openid scope → an ID token, from the same issuer.
    let id_token = response.id_token.expect("id_token");
    let header = jsonwebtoken::decode_header(&id_token).unwrap();
    assert_eq!(
        header.kid.as_deref(),
        Some(signer.jwks().keys[0].kid.as_str())
    );
    let unverified: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(id_token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(unverified["iss"], issuer.canonical_url.as_str());
}

#[tokio::test]
async fn test_issue_tokens_without_openid_scope() {
    let server = OAuth2Server::new(create_test_jwt());
    let (issuers, issuer) = crate::test_support::installation_issuer().await;
    let signer = issuers.signer(&issuer).await.unwrap();
    let profile = create_test_profile();
    let session = create_test_session(&profile);
    let client = create_test_client();
    let target = orders_target(&client);
    let scopes = vec!["profile".to_string()];

    let (response, _) = server
        .issue_tokens(
            &signer,
            &profile.id.to_string(),
            &profile,
            &session,
            &client,
            &target,
            &scopes,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("Token issuance should succeed");

    assert!(response.id_token.is_none()); // No openid scope → no id_token
}

#[test]
fn test_s256_challenge() {
    // RFC 7636 Appendix B example
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert_eq!(compute_s256_challenge(verifier), expected);
}
